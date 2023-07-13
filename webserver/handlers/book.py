#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import functools
import logging
import os
import queue
import random
import re
import subprocess
import threading
import time
import urllib
from gettext import gettext as _

import tornado.escape
from tornado import web

from webserver import constants, loader, utils
from webserver.handlers.base import BaseHandler, ListHandler, auth, js
from webserver.models import Item
from webserver.plugins.meta import baike, douban

CONF = loader.get_settings()
_q = queue.Queue()


def background(func):
    @functools.wraps(func)
    def run(*args, **kwargs):
        def worker():
            try:
                func(*args, **kwargs)
            except:
                import logging
                import traceback

                logging.error("Failed to run background task:")
                logging.error(traceback.format_exc())

        t = threading.Thread(name="worker", target=worker)
        t.setDaemon(True)
        t.start()

    return run


def do_ebook_convert(old_path, new_path, log_path):
    """convert book, and block, and wait"""
    args = ["ebook-convert", old_path, new_path]
    if new_path.lower().endswith(".epub"):
        args += ["--flow-size", "0"]

    timeout = 300
    try:
        timeout = int(CONF["convert_timeout"])
    except:
        pass

    with open(log_path, "w") as log:
        cmd = " ".join("'%s'" % v for v in args)
        logging.info("CMD: %s" % cmd)
        p = subprocess.Popen(args, stdout=log, stderr=subprocess.PIPE)
        try:
            _, stde = p.communicate(timeout=timeout)
            logging.info("ebook-convert finish: %s, err: %s" % (new_path, bytes.decode(stde)))
        except subprocess.TimeoutExpired:
            p.kill()
            logging.info("ebook-convert timeout: %s" % new_path)
            log.info("ebook-convert timeout: %s" % new_path)
            log.write(u"\n服务器转换书本格式时超时了。请在配置管理页面调大超时时间。\n[FINISH]")
            return False
        return True


class Index(BaseHandler):
    def fmt(self, b):
        return utils.BookFormatter(self, b).format()

    @js
    def get(self):
        cnt_reading = min(int(self.get_argument("reading", 8)), 30)
        cnt_random = min(int(self.get_argument("random", 8)), 30)
        cnt_recent = min(int(self.get_argument("recent", 10)), 30)

        # nav = "index"
        # title = _(u"全部书籍")
        ids = list(self.cache.search(""))
        if not ids:
            raise web.HTTPError(404, reason=_(u"本书库暂无藏书"))
        random_ids = random.sample(ids, min(cnt_random, len(ids)))
        random_books = [b for b in self.get_books(ids=random_ids) if b["cover"]]
        random_books.sort(key=lambda x: x["id"], reverse=True)

        ids.sort(reverse=True)
        new_ids = random.sample(ids[0:100], min(cnt_recent, len(ids)))
        new_books = [b for b in self.get_books(ids=new_ids) if b["cover"]]
        new_books.sort(key=lambda x: x["id"], reverse=True)

        return {
            "random_books_count": len(random_books),
            "new_books_count": len(new_books),
            "random_books": [self.fmt(b) for b in random_books],
            "new_books": [self.fmt(b) for b in new_books],
        }


class BookDetail(BaseHandler):
    @js
    def get(self, id):
        book = self.get_book(id)
        return {
            "err": "ok",
            "kindle_sender": CONF["smtp_username"],
            "book": utils.BookFormatter(self, book).format(with_files=True, with_perms=True),
        }


class BookRefer(BaseHandler):
    def has_proper_book(self, books, mi):
        if not books or not mi.isbn or mi.isbn == baike.BAIKE_ISBN:
            return False

        for b in books:
            if mi.isbn == b.get("isbn13", "xxx"):
                return True
            if mi.title == b.get("title") and mi.publisher == b.get("publisher"):
                return True
        return False

    def plugin_search_books(self, mi):
        title = re.sub(u"[(（].*", "", mi.title)
        api = douban.DoubanBookApi(
            CONF["douban_apikey"],
            CONF["douban_baseurl"],
            copy_image=False,
            manual_select=False,
            maxCount=CONF["douban_max_count"],
        )
        # first, search title
        books = []
        try:
            books = api.search_books(title) or []
        except:
            logging.error(_(u"豆瓣接口查询 %s 失败" % title))

        if not self.has_proper_book(books, mi):
            # 若有ISBN号，但是却没搜索出来，则精准查询一次ISBN
            # 总是把最佳书籍放在第一位
            book = api.get_book_by_isbn(mi.isbn)
            if book:
                books = list(books)
                books.insert(0, book)
        books = [api._metadata(b) for b in books]

        # append baidu book
        api = baike.BaiduBaikeApi(copy_image=False)
        try:
            book = api.get_book(title)
        except:
            return {"err": "httprequest.baidubaike.failed", "msg": _(u"百度百科查询失败")}
        if book:
            books.append(book)
        return books

    def plugin_get_book_meta(self, provider_key, provider_value, mi):
        if provider_key == baike.KEY:
            title = re.sub(u"[(（].*", "", mi.title)
            api = baike.BaiduBaikeApi(copy_image=True)
            try:
                return api.get_book(title)
            except:
                return {"err": "httprequest.baidubaike.failed", "msg": _(u"百度百科查询失败")}

        if provider_key == douban.KEY:
            mi.douban_id = provider_value
            api = douban.DoubanBookApi(
                CONF["douban_apikey"],
                CONF["douban_baseurl"],
                copy_image=True,
                maxCount=CONF["douban_max_count"],
            )
            try:
                return api.get_book(mi)
            except:
                return {"err": "httprequest.douban.failed", "msg": _(u"豆瓣接口查询失败")}
        return {"err": "params.provider_key.not_support", "msg": _(u"不支持该provider_key")}

    @js
    @auth
    def get(self, id):
        book_id = int(id)
        mi = self.db.get_metadata(book_id, index_is_id=True)
        books = self.plugin_search_books(mi)
        keys = [
            "cover_url",
            "source",
            "website",
            "title",
            "author_sort",
            "publisher",
            "isbn",
            "comments",
            "provider_key",
            "provider_value",
        ]
        rsp = []
        for b in books:
            d = dict((k, b.get(k, "")) for k in keys)
            pubdate = b.get("pubdate")
            d["pubyear"] = pubdate.strftime("%Y") if pubdate else ""
            if not d["comments"]:
                d["comments"] = _(u"无详细介绍")
            rsp.append(d)
        return {"err": "ok", "books": rsp}

    @js
    @auth
    def post(self, id):
        provider_key = self.get_argument("provider_key", "error")
        provider_value = self.get_argument("provider_value", "")
        only_meta = self.get_argument("only_meta", "")
        only_cover = self.get_argument("only_cover", "")
        book_id = int(id)
        if not provider_key:
            return {"err": "params.provider_key.invalid", "msg": _(u"provider_key参数错误")}
        if not provider_value:
            return {"err": "params.provider_key.invalid", "msg": _(u"provider_value参数错误")}
        if only_meta == "yes" and only_cover == "yes":
            return {"err": "params.conflict", "msg": _(u"参数冲突")}

        mi = self.db.get_metadata(book_id, index_is_id=True)
        if not mi:
            return {"err": "params.book.invalid", "msg": _(u"书籍不存在")}
        if not self.is_admin() and not self.is_book_owner(book_id, self.user_id()):
            return {"err": "user.no_permission", "msg": _(u"无权限")}

        refer_mi = self.plugin_get_book_meta(provider_key, provider_value, mi)
        if only_cover == "yes":
            # just set cover
            mi.cover_data = refer_mi.cover_data
        else:
            if only_meta == "yes":
                refer_mi.cover_data = None
            if len(refer_mi.tags) == 0 and len(mi.tags) == 0:
                ts = []
                for nn, tags in constants.BOOKNAV:
                    for tag in tags:
                        if tag in refer_mi.title or tag in refer_mi.comments:
                            ts.append(tag)
                        elif tag in refer_mi.authors:
                            ts.append(tag)
                if len(ts) > 0:
                    mi.tags += ts[:8]
                    logging.info("tags are %s" % ','.join(mi.tags))
                    self.db.set_tags(book_id, mi.tags)
            mi.smart_update(refer_mi, replace_metadata=True)

        self.db.set_metadata(book_id, mi)
        return {"err": "ok"}


class BookEdit(BaseHandler):
    @js
    @auth
    def post(self, bid):
        book = self.get_book(bid)
        bid = book["id"]
        if isinstance(book["collector"], dict):
            cid = book["collector"]["id"]
        else:
            cid = book["collector"].id
        if not self.current_user.can_edit() or not (self.is_admin() or self.is_book_owner(bid, cid)):
            return {"err": "permission", "msg": _(u"无权操作")}

        data = tornado.escape.json_decode(self.request.body)
        mi = self.db.get_metadata(bid, index_is_id=True)
        KEYS = [
            "authors",
            "title",
            "comments",
            "tags",
            "publisher",
            "isbn",
            "series",
            "rating",
            "language",
        ]
        for key, val in data.items():
            if key in KEYS:
                mi.set(key, val)

        if data.get("pubdate", None):
            content = douban.str2date(data["pubdate"])
            if content is None:
                return {"err": "params.pudate.invalid", "msg": _(u"出版日期参数错误，格式应为 2019-05-10或2019-05或2019年或2019")}
            mi.set("pubdate", content)

        if "tags" in data and not data["tags"]:
            self.db.set_tags(bid, [])

        self.db.set_metadata(bid, mi)
        return {"err": "ok", "msg": _(u"更新成功")}


class BookDelete(BaseHandler):
    @js
    @auth
    def post(self, bid):
        book = self.get_book(bid)
        bid = book["id"]
        if isinstance(book["collector"], dict):
            cid = book["collector"]["id"]
        else:
            cid = book["collector"].id
        if not self.current_user.can_edit() or not (self.is_admin() or self.is_book_owner(bid, cid)):
            return {"err": "permission", "msg": _(u"无权操作")}

        if not self.current_user.can_delete() or not (self.is_admin() or self.is_book_owner(bid, cid)):
            return {"err": "permission", "msg": _(u"无权操作")}

        self.db.delete_book(bid)
        self.add_msg("success", _(u"删除书籍《%s》") % book["title"])
        return {"err": "ok", "msg": _(u"删除成功")}


class BookDownload(BaseHandler):
    def send_error_of_not_invited(self):
        self.set_header("WWW-Authenticate", "Basic")
        self.set_status(401)
        raise web.Finish()

    def get(self, id, fmt):
        is_opds = self.get_argument("from", "") == "opds"
        if not CONF["ALLOW_GUEST_DOWNLOAD"] and not self.current_user:
            if is_opds:
                return self.send_error_of_not_invited()
            else:
                return self.redirect("/login")

        if self.current_user:
            if self.current_user.can_save():
                if not self.current_user.is_active():
                    raise web.HTTPError(403, reason=_(u"无权操作，请先登录注册邮箱激活账号。"))
            else:
                raise web.HTTPError(403, reason=_(u"无权操作"))

        fmt = fmt.lower()
        logging.debug("download %s.%s" % (id, fmt))
        book = self.get_book(id)
        book_id = book["id"]
        self.user_history("download_history", book)
        self.count_increase(book_id, count_download=1)
        if "fmt_%s" % fmt not in book:
            raise web.HTTPError(404, reason=_(u"%s格式无法下载" % fmt))
        path = book["fmt_%s" % fmt]
        book["fmt"] = fmt
        book["title"] = urllib.parse.quote_plus(book["title"])
        fname = "%(id)d-%(title)s.%(fmt)s" % book
        att = u"attachment; filename=\"%s\"; filename*=UTF-8''%s" % (fname, fname)
        if is_opds:
            att = u'attachment; filename="%(id)d.%(fmt)s"' % book

        self.set_header("Content-Disposition", att.encode("UTF-8"))
        self.set_header("Content-Type", "application/octet-stream")
        with open(path, "rb") as f:
            self.write(f.read())


class BookNav(ListHandler):
    @js
    def get(self):
        tagmap = self.all_tags_with_count()
        navs = []
        for h1, tags in constants.BOOKNAV:
            new_tags = [{"name": v, "count": tagmap.get(v, 0)} for v in tags if tagmap.get(v, 0) > 0]
            navs.append({"legend": h1, "tags": new_tags})
        return {"err": "ok", "navs": navs}


class RecentBook(ListHandler):
    def get(self):
        title = _(u"新书推荐")
        ids = self.books_by_id()
        return self.render_book_list([], ids=ids, title=title, sort_by_id=True)


class SearchBook(ListHandler):
    def get(self):
        name = self.get_argument("name", "")
        if not name.strip():
            return self.write({"err": "params.invalid", "msg": _(u"请输入搜索关键字")})

        title = _(u"搜索：%(name)s") % {"name": name}
        ids = self.cache.search(name)
        return self.render_book_list([], ids=ids, title=title)


class HotBook(ListHandler):
    def get(self):
        title = _(u"热度榜单")
        db_items = self.session.query(Item).filter(Item.count_visit > 1).order_by(Item.count_download.desc())
        count = db_items.count()
        start = self.get_argument_start()
        delta = 60
        page_max = int(count / delta)
        page_now = int(start / delta)
        pages = []
        for p in range(page_now - 3, page_now + 3):
            if 0 <= p and p <= page_max:
                pages.append(p)
        items = db_items.limit(delta).offset(start).all()
        ids = [item.book_id for item in items]
        books = self.get_books(ids=ids)
        self.do_sort(books, "count_download", False)
        return self.render_book_list(books, title=title)


class BookUpload(BaseHandler):
    @classmethod
    def convert(cls, s):
        try:
            return s.group(0).encode("latin1").decode("utf8")
        except:
            return s.group(0)

    def get_upload_file(self):
        # for unittest mock
        p = self.request.files["ebook"][0]
        return (p["filename"], p["body"])

    @js
    @auth
    def post(self):
        from calibre.ebooks.metadata.meta import get_metadata

        if not self.current_user.can_upload():
            return {"err": "permission", "msg": _(u"无权操作")}
        name, data = self.get_upload_file()
        name = re.sub(r"[\x80-\xFF]+", BookUpload.convert, name)
        logging.error("upload book name = " + repr(name))
        fmt = os.path.splitext(name)[1]
        fmt = fmt[1:] if fmt else None
        if not fmt:
            return {"err": "params.filename", "msg": _(u"文件名不合法")}
        fmt = fmt.lower()

        # save file
        fpath = os.path.join(CONF["upload_path"], name)
        with open(fpath, "wb") as f:
            f.write(data)
        logging.debug("save upload file into [%s]", fpath)

        # read ebook meta
        with open(fpath, "rb") as stream:
            mi = get_metadata(stream, stream_type=fmt, use_libprs_metadata=True)

        if fmt.lower() == "txt":
            mi.title = name.replace(".txt", "")
            mi.authors = [_(u"佚名")]
        logging.info("upload mi.title = " + repr(mi.title))
        books = self.db.books_with_same_title(mi)
        if books:
            book_id = books.pop()
            return {
                "err": "samebook",
                "msg": _(u"已存在同名书籍《%s》") % mi.title,
                "book_id": book_id,
            }

        fpaths = [fpath]
        book_id = self.db.import_book(mi, fpaths)
        self.user_history("upload_history", {"id": book_id, "title": mi.title})
        self.add_msg("success", _(u"导入书籍成功！"))
        item = Item()
        item.book_id = book_id
        item.collector_id = self.user_id()
        item.save()
        return {"err": "ok", "book_id": book_id}


class BookRead(BaseHandler):
    def get(self, id):
        if not CONF["ALLOW_GUEST_READ"] and not self.current_user:
            return self.redirect("/login")

        if self.current_user:
            if self.current_user.can_read():
                if not self.current_user.is_active():
                    raise web.HTTPError(403, reason=_(u"无权在线阅读，请先登录注册邮箱激活账号。"))
            else:
                raise web.HTTPError(403, reason=_(u"无权在线阅读"))

        book = self.get_book(id)
        book_id = book["id"]
        self.user_history("read_history", book)
        self.count_increase(book_id, count_download=1)

        # check format
        for fmt in ["epub", "mobi", "azw", "azw3", "txt"]:
            fpath = book.get("fmt_%s" % fmt, None)
            if not fpath:
                continue
            # epub_dir is for javascript
            epub_dir = "/get/extract/%s" % book["id"]
            is_ready = self.is_ready(book)
            self.extract_book(book, fpath, fmt)
            return self.html_page("book/read.html", {
                "book": book,
                "epub_dir": epub_dir,
                "is_ready": is_ready,
            })

        if "fmt_pdf" in book:
            # PDF类书籍需要检查下载权限。
            if not CONF["ALLOW_GUEST_DOWNLOAD"] and not self.current_user:
                return self.redirect("/login")

            if self.current_user and not self.current_user.can_save():
                raise web.HTTPError(403, reason=_(u"无权在线阅读PDF类书籍"))

            pdf_url = urllib.parse.quote_plus(self.api_url + "/api/book/%(id)d.PDF" % book)
            pdf_reader_url = CONF["PDF_VIEWER"] % {"pdf_url": pdf_url}
            return self.redirect(pdf_reader_url)

        raise web.HTTPError(404, reason=_(u"抱歉，在线阅读器暂不支持该格式的书籍"))

    def is_ready(self, book):
        # 解压后的目录
        fdir = os.path.join(CONF["extract_path"], str(book["id"]))
        return os.path.isfile(fdir + "/META-INF/container.xml")

    @background
    def extract_book(self, book, fpath, fmt):
        # 解压后的目录
        fdir = os.path.join(CONF["extract_path"], str(book["id"]))
        subprocess.call(["mkdir", "-p", fdir])
        if os.path.isfile(fdir + "/META-INF/container.xml"):
            subprocess.call(["chmod", "a+rx", "-R", fdir + "/META-INF"])
            return

        progress_file = self.get_path_progress(book["id"])
        new_path = ""
        if fmt != "epub":
            new_fmt = "epub"
            new_path = os.path.join(
                CONF["convert_path"],
                "book-%s-%s.%s" % (book["id"], int(time.time()), new_fmt),
            )
            logging.info("convert book: %s => %s, progress: %s" % (fpath, new_path, progress_file))
            os.chdir("/tmp/")

            ok = do_ebook_convert(fpath, new_path, progress_file)
            if not ok:
                self.add_msg("danger", u"文件格式转换失败，请在QQ群里联系管理员.")
                return

            with open(new_path, "rb") as f:
                self.db.add_format(book["id"], new_fmt, f, index_is_id=True)
                logging.info("add new book: %s", new_path)
            fpath = new_path

        # extract to dir
        logging.error("extract book: [%s] into [%s]", fpath, fdir)
        os.chdir(fdir)
        with open(progress_file, "a") as log:
            log.write(u"Dir: %s\n" % fdir)
            subprocess.call(["unzip", fpath, "-d", fdir], stdout=log)
            subprocess.call(["chmod", "a+rx", "-R", fdir + "/META-INF"])
            if new_path:
                subprocess.call(["rm", new_path])
        return


class BookPush(BaseHandler):
    @js
    def post(self, id):
        if not CONF["ALLOW_GUEST_PUSH"]:
            if not self.current_user:
                return {"err": "user.need_login", "msg": _(u"请先登录")}
            else:
                if not self.current_user.can_push():
                    return {"err": "permission", "msg": _(u"无权操作")}
                elif not self.current_user.is_active():
                    return {"err": "permission", "msg": _(u"无权操作，请先激活账号。")}

        mail_to = self.get_argument("mail_to", None)
        if not mail_to:
            return {"err": "params.error", "msg": _(u"参数错误")}

        book = self.get_book(id)
        book_id = book["id"]

        self.user_history("push_history", book)
        self.count_increase(book_id, count_download=1)

        # https://www.amazon.cn/gp/help/customer/display.html?ref_=hp_left_v4_sib&nodeId=G5WYD9SAF7PGXRNA
        for fmt in ["epub", "pdf"]:
            fpath = book.get("fmt_%s" % fmt, None)
            if fpath:
                self.bg_send_book(book, mail_to, fmt, fpath)
                return {"err": "ok", "msg": _(u"服务器后台正在推送了。您可关闭此窗口，继续浏览其他书籍。")}

        # we do no have formats for kindle
        if "fmt_azw3" not in book and "fmt_txt" not in book:
            return {
                "err": "book.no_format_for_kindle",
                "msg": _(u"抱歉，该书无可用于kindle阅读的格式"),
            }

        self.bg_convert_and_send(book, mail_to)
        self.add_msg(
            "success",
            _(u"服务器正在推送《%(title)s》到%(email)s") % {"title": book["title"], "email": mail_to},
        )
        return {"err": "ok", "msg": _(u"服务器正在转换格式，稍后将自动推送。您可关闭此窗口，继续浏览其他书籍。")}

    @background
    def bg_send_book(self, book, mail_to, fmt, fpath):
        self.do_send_mail(book, mail_to, fmt, fpath)

    @background
    def bg_convert_and_send(self, book, mail_to):
        # https://www.amazon.cn/gp/help/customer/display.html?ref_=hp_left_v4_sib&nodeId=G5WYD9SAF7PGXRNA
        fmt = "epub"  # best format for kindle
        fpath = self.convert_to_mobi_format(book, fmt)
        if fpath:
            self.do_send_mail(book, mail_to, fmt, fpath)

    def get_path_of_fmt(self, book, fmt):
        """for mock test"""
        from calibre.utils.filenames import ascii_filename

        return os.path.join(CONF["convert_path"], "%s.%s" % (ascii_filename(book["title"]), fmt))

    def convert_to_mobi_format(self, book, new_fmt):
        new_path = self.get_path_of_fmt(book, new_fmt)
        progress_file = self.get_path_progress(book["id"])

        old_path = None
        for f in ["txt", "azw3"]:
            old_path = book.get("fmt_%s" % f, old_path)

        logging.debug("convert book from [%s] to [%s]", old_path, new_path)
        ok = do_ebook_convert(old_path, new_path, progress_file)
        if not ok:
            self.add_msg("danger", u"文件格式转换失败，请在QQ群里联系管理员.")
            return None
        with open(new_path, "rb") as f:
            self.db.add_format(book["id"], new_fmt, f, index_is_id=True)
        return new_path

    def do_send_mail(self, book, mail_to, fmt, fpath):
        from calibre.ebooks.metadata import authors_to_string

        # read meta info
        author = authors_to_string(book["authors"] if book["authors"] else [_(u"佚名")])
        title = book["title"] if book["title"] else _(u"无名书籍")
        fname = u"%s - %s.%s" % (title, author, fmt)
        with open(fpath, "rb") as f:
            fdata = f.read()

        mail_args = {
            "title": title,
            "site_url": self.site_url,
            "site_title": CONF["site_title"],
        }
        mail_from = self.settings["smtp_username"]
        mail_subject = _(self.settings["push_title"]) % mail_args
        mail_body = _(self.settings["push_content"]) % mail_args
        status = msg = ""
        try:
            logging.info("send %(title)s to %(mail_to)s" % vars())
            self.mail(mail_from, mail_to, mail_subject, mail_body, fdata, fname)
            status = "success"
            msg = _("[%(title)s] 已成功发送至Kindle邮箱 [%(mail_to)s] !!") % vars()
            logging.info(msg)
        except:
            import traceback

            logging.error("Failed to send to kindle: %s" % mail_to)
            logging.error(traceback.format_exc())
            status = "danger"
            msg = traceback.format_exc()
        self.add_msg(status, msg)
        return


def routes():
    return [
        (r"/api/index", Index),
        (r"/api/search", SearchBook),
        (r"/api/recent", RecentBook),
        (r"/api/hot", HotBook),
        (r"/api/book/nav", BookNav),
        (r"/api/book/upload", BookUpload),
        (r"/api/book/([0-9]+)", BookDetail),
        (r"/api/book/([0-9]+)/delete", BookDelete),
        (r"/api/book/([0-9]+)/edit", BookEdit),
        (r"/api/book/([0-9]+)\.(.+)", BookDownload),
        (r"/api/book/([0-9]+)/push", BookPush),
        (r"/api/book/([0-9]+)/refer", BookRefer),
        (r"/read/([0-9]+)", BookRead),
    ]
