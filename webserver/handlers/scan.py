#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import hashlib
import logging
import os
import threading
import time
import traceback
from gettext import gettext as _

import sqlalchemy
import tornado

from webserver import loader
from webserver.handlers.base import BaseHandler, auth, js, is_admin
from webserver.models import Item, ScanFile

CONF = loader.get_settings()
SCAN_EXT = ["azw", "azw3", "epub", "mobi", "pdf", "txt"]
SCAN_DIR_PREFIX = "/data/"  # 限定扫描必须在/data/目录下，以防黑客扫描到其他系统目录


class Scanner:
    def __init__(self, calibre_db, ScopedSession, user_id=None):
        self.db = calibre_db
        self.user_id = user_id
        self.func_new_session = ScopedSession
        self.curret_thread = threading.get_ident()
        self.bind_new_session()

    def bind_new_session(self):
        # NOTE 起线程后台运行后，如果不开新的session，会出现session对象的绑定错误
        self.session = self.func_new_session()

    def allow_backgrounds(self):
        """for unittest control"""
        return True

    def resume_last_scan(self):
        # TODO
        return False

    def save_or_rollback(self, row):
        try:
            row.save()
            self.session.commit()
            bid = "[ book-id=%s ]" % row.book_id
            logging.error("update: status=%-5s, path=%s %s", row.status, row.path, bid if row.book_id > 0 else "")
            return True
        except Exception as err:
            logging.error(traceback.format_exc())
            self.session.rollback()
            logging.warn("save error: %s", err)
            return False
        

    def save_or_rollback_batch(self, rows):
        try:
            # for row in rows:
                # bid = "[ book-id=%s ]" % row.book_id
                # row.save()
                # logging.error("update: status=%-5s, path=%s %s", row.status, row.path, bid if row.book_id > 0 else "")
            self.session.bulk_save_objects(rows)
            logging.error("========== insert/update saved.")
            self.session.commit()
            logging.error("========== insert/update transaction committed.")
            return True
        except Exception as err:
            logging.error(traceback.format_exc())
            self.session.rollback()
            logging.warn("save error: %s", err)
            return False
        
    def paginate(self, items, per_page):
        pages = [items[i:i+per_page] for i in range(0, len(items), per_page)]
        return {
            'total': len(items),
            'pages_no': len(pages),
            'pages': pages
        }

    def run_scan(self, path_dir):
        if self.resume_last_scan():
            return 1

        if not self.allow_backgrounds():
            self.do_scan(path_dir)
        else:
            logging.error("run into background thread")
            t = threading.Thread(name="do_scan", target=self.do_scan, args=(path_dir,))
            t.setDaemon(True)
            t.start()
        return 1
    


    def run_updateFileSize(self, path_dir):
        if self.resume_last_scan():
            return 1

        if not self.allow_backgrounds():
            self.do_updateFileSize(path_dir)
        else:
            logging.error("run into background thread")
            t = threading.Thread(name="do_updateFileSize", target=self.do_updateFileSize, args=(path_dir,))
            t.setDaemon(True)
            t.start()
        return 1
    

    
    
    def query_scanned_books_by_path(self, fpath):
        query = self.session.query(ScanFile)
        query = query.filter(ScanFile.path == fpath)
        return query.first()
    
    def query_scanned_books_by_status(self, status):
        query = self.session.query(ScanFile)
        query = query.filter(ScanFile.status == status)
        return query.all()
    
    def query_scanned_books_all(self):
        query = self.session.query(ScanFile)
        return query.all()
    

    def query_scanned_books_no_filesize(self):
        query = self.session.query(ScanFile).filter(ScanFile.file_size in [None, 0])
        return query.all()
    

    
    

    def do_updateFileSize(self, path_dir):
        allScannedFilesDB = self.query_scanned_books_all()
        sumsize = 0
        for row in allScannedFilesDB:
            if os.path.exists(row.path) and os.path.isfile(row.path):
                file_size_kb = os.stat(row.path).st_size/(1024)
                row.file_size=int(file_size_kb)
                sumsize += int(file_size_kb)

        logging.info('sumsize:' + str(sumsize) + 'kb')
        # pages = self.paginate(allScannedFilesDB, 100)
        # for page in pages['pages']:
        #     self.save_or_rollback_batch(page)
            # self.session.bulk_save_objects(page)
            # self.session.commit()



    def do_scan(self, path_dir):
        from calibre.ebooks.metadata.meta import get_metadata

        if threading.get_ident() != self.curret_thread:
            self.bind_new_session()

        # 生成任务（粗略扫描），前端可以调用API查询进展

        # 遍历配置目录下的所有书籍
        allFilePathesInDir = []
        for dirpath, __, filenames in os.walk(path_dir):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                if not os.path.isfile(fpath):
                    continue
                fmt = fpath.split(".")[-1].lower()
                if fmt not in SCAN_EXT:
                    # logging.debug("bad format: [%s] %s", fmt, fpath)
                    continue
                allFilePathesInDir.append(fpath)

        # 查询数据库所有数据
        allScannedFilesDB = self.query_scanned_books_all()
        pathsExsitedDB = [o.path for o in allScannedFilesDB]
        hashsExistedDB = [o.hash for o in allScannedFilesDB]

        #比较得出需要添加的数据
        tasks = [fpath for fpath in allFilePathesInDir if fpath not in pathsExsitedDB]    
        # 生成任务ID
        scan_id = int(time.time())
        logging.info("========== start to insert webserver.scanfiles ============")

        # 写入新的文件信息到数据库
        tasksPage = self.paginate(tasks, 100)
        totalPage = tasksPage['pages_no']
        logging.info("========== insert totalPage: " + str(totalPage))
        curPageNum = 0
        for taskPage in tasksPage["pages"]:
            rows_new = []
            for fpath in taskPage:
                fsize = os.stat(fpath).st_size
                md5 = self.cal_file_md5(fpath)
                sha1 = self.cal_file_sha1(fpath)
                hash_value = "fstat:%s/md5:%s/sha1:%s" % (fsize, md5, sha1)
                if hash_value in hashsExistedDB:
                    continue
                else:
                    rows_new.append(ScanFile(fpath, hash_value, scan_id))

            logging.info("========== batch insert webserver.scanfiles. for pageNum: " + str(curPageNum))
            curPageNum = curPageNum + 1
            if not self.save_or_rollback_batch(rows_new):
                logging.error("========== batch insert webserver.scanfiles failed.")
                continue
            logging.info("========== batch insert webserver.scanfiles successfully.")

        logging.info("========== start to query scanfiles by new status ============")
        all_scanned_files_in_db_new = self.query_scanned_books_by_status("new")

        logging.info("========== start to fetch metadate from file and update tables ============")
        rows_update = all_scanned_files_in_db_new;
   
        pageRst = self.paginate(rows_update, 100);
        totalPage = pageRst['pages_no']
        logging.info("========== update totalPage: " + str(totalPage))
        curPageNum = 0;
        for page in pageRst['pages']:
            for row in page:
                fpath = row.path

                # 尝试解析metadata
                logging.info("========== fetch metadate for " + fpath)
                fmt = fpath.split(".")[-1].lower()
                with open(fpath, "rb") as stream:
                    mi = get_metadata(stream, stream_type=fmt, use_libprs_metadata=True)
                logging.info("========== fetch metadate end.")
                row.title = mi.title
                row.author = mi.author_sort
                row.publisher = mi.publisher
                row.tags = ", ".join(mi.tags)
                row.status = ScanFile.READY  # 设置为可处理

                # TODO calibre提供的书籍重复接口只有对比title；应当提前对整个书库的文件做哈希，才能准确去重
                logging.info("========== compare title to calibre for " + row.title)
                books = self.db.books_with_same_title(mi)
                logging.info("========== compare title to calibre end.")
                if books:
                    row.book_id = books.pop()
                    row.status = ScanFile.EXIST
            logging.info("========== batch update webserver.scanfiles. for pageNum: " + str(curPageNum))
            curPageNum = curPageNum + 1
            if not self.save_or_rollback_batch(page):
                logging.error("========== batch update webserver.scanfiles failed.")
                continue
            logging.info("========== batch update webserver.scanfiles successfully.")
        return True
    


    def delete(self, hashlist):
        query = self.session.query(ScanFile)
        if isinstance(hashlist, (list, tuple)):
            query = query.filter(ScanFile.hash.in_(hashlist))
        elif isinstance(hashlist, str):
            query = query.filter(ScanFile.hash == hashlist)
        count = query.delete()
        self.session.commit()
        return count

    def resume_last_import(self):
        # TODO
        return False

    def build_query(self, hashlist):
        query = self.session.query(ScanFile).filter(
            ScanFile.status == ScanFile.READY
        )  # .filter(ScanFile.import_id == 0)
        if isinstance(hashlist, (list, tuple)):
            query = query.filter(ScanFile.hash.in_(hashlist))
        elif isinstance(hashlist, str):
            query = query.filter(ScanFile.hash == hashlist)
        return query

    def run_import(self, hashlist):
        if self.resume_last_import():
            return 1

        total = self.build_query(hashlist).count()

        if not self.allow_backgrounds():
            self.do_import(hashlist, None)
        else:
            logging.info("run into background thread")
            t = threading.Thread(name="do_import", target=self.do_import, args=(hashlist, None))
            t.setDaemon(True)
            t.start()
        return total
    

    def get_query_for_scanned_books_by_ready_and_strict(self):
        return self.session.query(ScanFile).filter(
                sqlalchemy.and_(ScanFile.status.is_('ready'),
                                ScanFile.author.is_not(None),ScanFile.author.is_not(''),ScanFile.author.is_not('Unknown'), ScanFile.author.is_not('未知'),
                                ScanFile.publisher.is_not(None), ScanFile.publisher.is_not(''), ScanFile.publisher.is_not('Unknown'), ScanFile.publisher.is_not('未知')
                                )
                            )


    def run_import_auto(self):
        if self.resume_last_import():
            return 1

        query = self.get_query_for_scanned_books_by_ready_and_strict().all()
        pageObj = self.paginate(query, 100)
        total = pageObj['total']
        logging.info('batch auto import. total: %s, pageCount: %s' % (total, pageObj['pages_no']))
        if not self.allow_backgrounds():
            self.do_import_batch(pageObj['pages'])
        else:
            logging.info("run into background thread")
            t = threading.Thread(name="do_import_batch", target=self.do_import_batch, args=(pageObj['pages'],))
            t.setDaemon(True)
            t.start()
        return total
    

    
    def do_import_batch(self, pages):
        # 生成任务ID
        import_id = int(time.time())
        for page in pages:
            self.do_import([row.hash for row in page], import_id)


    def do_import(self, hashlist, import_id):
        from calibre.ebooks.metadata.meta import get_metadata

        if threading.get_ident() != self.curret_thread:
            self.bind_new_session()


        query = self.build_query(hashlist)
        query.update({ScanFile.import_id: (import_id or int(time.time()))}, synchronize_session=False)
        self.session.commit()

        rows = []
        existRows = []
        items = []
        # 逐个处理
        for row in query.all():
            fpath = row.path
            fmt = fpath.split(".")[-1].lower()
            with open(fpath, "rb") as stream:
                mi = get_metadata(stream, stream_type=fmt, use_libprs_metadata=True)

            # 再次检查是否有重复书籍
            books = self.db.books_with_same_title(mi)
            if books:
                row.status = ScanFile.EXIST
                row.book_id = books.pop()
                existRows.append(row)
                continue

            # 组装记录为已导入
            logging.info("import [%s] from %s", mi.title, fpath)
            row.book_id = self.db.import_book(mi, [fpath])
            row.status = ScanFile.IMPORTED
            rows.append(row)

            # 添加关联表
            item = Item()
            item.book_id = row.book_id
            item.collector_id = self.user_id
            items.append(item)
        logging.info("batch update table:scanfiles for newImport")
        self.save_or_rollback_batch(rows)
        logging.info("batch update table:scanfiles for existed")
        self.save_or_rollback_batch(existRows)
        try:
            logging.info("batch update table:item")
            self.save_or_rollback_batch(items)
        except Exception as err:
            self.session.rollback()
            logging.error("save link error: %s", err)
        return True

    def import_status(self):
        import_id = self.session.query(sqlalchemy.func.max(ScanFile.import_id)).scalar()
        if import_id is None:
            return (0, {})
        query = self.session.query(ScanFile.status).filter(ScanFile.import_id == import_id)
        return (import_id, self.count(query))

    def scan_status(self):
        scan_id = self.session.query(sqlalchemy.func.max(ScanFile.scan_id)).scalar()
        if scan_id is None:
            return (0, {})
        query = self.session.query(ScanFile.status).filter(ScanFile.scan_id == scan_id)
        return (scan_id, self.count(query))

    def count(self, query):
        rows = query.all()
        count = {
            "total": len(rows),
            ScanFile.NEW: 0,
            ScanFile.DROP: 0,
            ScanFile.EXIST: 0,
            ScanFile.READY: 0,
            ScanFile.IMPORTED: 0,
        }
        for row in rows:
            if row.status not in count:
                count[row.status] = 0
            count[row.status] += 1
        return count


    def cal_file_md5(self, file_path):
        with open(file_path, 'rb') as fp:
            data = fp.read()
            file_md5= hashlib.md5(data).hexdigest()
            return file_md5
        
    
    def cal_file_sha1(self, file_path):
        with open(file_path, 'rb') as fp:
            data = fp.read()
            file_sha1= hashlib.sha1(data).hexdigest()
            return file_sha1
        

    def run_fill_size_and_md5(self):
        allScanFilesInDB = self.query_scanned_books_all()
        # 分页
        hash_existed_list = [scan_file_db.hash for scan_file_db in allScanFilesInDB]
        pageTotal = self.paginate(allScanFilesInDB, 50)
        logging.info('total items:%s'%pageTotal['total'])
        logging.info('total page:%s'%pageTotal['pages_no'])
        for page in pageTotal['pages']:
            pageInsert = []
            for scanFileInDB in page:
                hash_value = scanFileInDB.hash
                file_path = scanFileInDB.path
                fsize = os.stat(scanFileInDB.path).st_size
                hashFormat = "fstat:%s/md5:%s/sha1:%s"
                # 生成hash值
                if "fstat:" in hash_value and "/md5:" in hash_value and "/sha1:" in hash_value: 
                    continue
                elif hash_value is None or 'sha1:' not in hash_value:
                    md5 = self.cal_file_md5(file_path)
                    sha1 = self.cal_file_sha1(file_path)
                    hash_value = hashFormat % (fsize, md5, sha1)
                else:
                    logging.error("unkown hash format. id:%s, hash:%s" % (str(scanFileInDB.id), scanFileInDB.hash))

                #判断hash有没有重复的
                if hash_value in hash_existed_list:
                    logging.error("exist file. id:%s, hash:%s, path:%s" % (str(scanFileInDB.id), hash_value, file_path))
                    continue
                else:
                    logging.info("update table scanfiles. id:%s, hash:%s" % (str(scanFileInDB.id), hash_value))
                    pageInsert.append(scanFileInDB)
                    hash_existed_list.append(hash_value)
            self.save_or_rollback_batch(pageInsert)

        return pageTotal['total']
                


class ScanList(BaseHandler):

    
    def get_query_for_scanned_books_by_ready_and_strict(self):
        return self.session.query(ScanFile).filter(
                sqlalchemy.and_(ScanFile.status.is_('ready'),
                                ScanFile.author.is_not(None),ScanFile.author.is_not(''),ScanFile.author.is_not('Unknown'), ScanFile.author.is_not('未知'),
                                ScanFile.publisher.is_not(None), ScanFile.publisher.is_not(''), ScanFile.publisher.is_not('Unknown'), ScanFile.publisher.is_not('未知')
                                )
                            )

    @js
    @auth
    def get(self):
        if not self.admin_user:
            return {"err": "permission.not_admin", "msg": _(u"当前用户非管理员")}

        num = max(10, int(self.get_argument("num", 20)))
        page = max(0, int(self.get_argument("page", 1)) - 1)
        sort = self.get_argument("sort", "access_time")
        desc = self.get_argument("desc", "desc")
        logging.debug("num=%d, page=%d, sort=%s, desc=%s" % (num, page, sort, desc))

        # get order by query args
        order = {
            "id": ScanFile.id,
            "path": ScanFile.path,
            "name": ScanFile.name,
            "create_time": ScanFile.create_time,
            "update_time": ScanFile.update_time,
        }.get(sort, ScanFile.create_time)
        order = order.asc() if desc == "false" else order.desc()
        # query = self.session.query(ScanFile).order_by(order)
        
        query = self.get_query_for_scanned_books_by_ready_and_strict().order_by(order)
        total = query.count()
        start = page * num

        response = []
        for s in query.limit(num).offset(start).all():
            d = {
                "id": s.id,
                "path": s.path,
                "hash": s.hash,
                "title": s.title,
                "author": s.author,
                "publisher": s.publisher,
                "tags": s.tags,
                "status": s.status,
                "book_id": s.book_id,
                "create_time": s.create_time.strftime("%Y-%m-%d %H:%M:%S") if s.create_time else "N/A",
                "update_time": s.update_time.strftime("%Y-%m-%d %H:%M:%S") if s.update_time else "N/A",
            }
            response.append(d)
        return {"err": "ok", "items": response, "total": total, "scan_dir": CONF["scan_upload_path"]}


class ScanMark(BaseHandler):
    @js
    @is_admin
    def post(self):
        return {"err": "ok", "msg": _(u"发送成功")}


class ScanRun(BaseHandler):
    @js
    @is_admin
    def post(self):
        path = CONF["scan_upload_path"]
        if not path.startswith(SCAN_DIR_PREFIX):
            return {"err": "params.error", "msg": _(u"书籍导入目录必须是%s的子目录") % SCAN_DIR_PREFIX}
        m = Scanner(self.db, self.settings["ScopedSession"])
        total = m.run_scan(path)
        if total == 0:
            return {"err": "empty", "msg": _("目录中没有找到符合要求的书籍文件！")}
        return {"err": "ok", "msg": _(u"开始扫描了"), "total": total}


class UpdateFileSize(BaseHandler):
    @js
    @is_admin
    def post(self):
        path = CONF["scan_upload_path"]
        if not path.startswith(SCAN_DIR_PREFIX):
            return {"err": "params.error", "msg": _(u"书籍导入目录必须是%s的子目录") % SCAN_DIR_PREFIX}
        m = Scanner(self.db, self.settings["ScopedSession"])
        total = m.run_updateFileSize(path)
        if total == 0:
            return {"err": "empty", "msg": _("目录中没有找到符合要求的书籍文件！")}
        return {"err": "ok", "msg": _(u"开始扫描了"), "total": total}



class ScanDelete(BaseHandler):
    @js
    @is_admin
    def post(self):
        req = tornado.escape.json_decode(self.request.body)
        hashlist = req["hashlist"]
        if not hashlist:
            return {"err": "params.error", "msg": _(u"参数错误")}
        if hashlist == "all":
            hashlist = None

        m = Scanner(self.db, self.settings["ScopedSession"])
        count = m.delete(hashlist)
        return {"err": "ok", "msg": _(u"删除成功"), "count": count}


class ScanStatus(BaseHandler):
    @js
    @is_admin
    def get(self):
        m = Scanner(self.db, self.settings["ScopedSession"])
        status = m.scan_status()[1]
        return {"err": "ok", "msg": _(u"成功"), "status": status}


class ImportRun(BaseHandler):
    @js
    @is_admin
    def post(self):
        req = tornado.escape.json_decode(self.request.body)
        hashlist = req["hashlist"]
        if not hashlist:
            return {"err": "params.error", "msg": _(u"参数错误")}
        if hashlist == "all":
            hashlist = None

        m = Scanner(self.db, self.settings["ScopedSession"], self.user_id())
        total = m.run_import(hashlist)
        if total == 0:
            return {"err": "empty", "msg": _("没有等待导入书库的书籍！")}
        return {"err": "ok", "msg": _(u"扫描成功")}



class AutoImportRun(BaseHandler):
    @js
    @is_admin
    def post(self):
        m = Scanner(self.db, self.settings["ScopedSession"], self.user_id())
        total = m.run_import_auto()
        if total == 0:
            return {"err": "empty", "msg": _("没有等待导入书库的书籍！")}
        return {"err": "ok", "msg": _(u"扫描成功")}


class ImportStatus(BaseHandler):
    @js
    @is_admin
    def get(self):
        m = Scanner(self.db, self.settings["ScopedSession"])
        status = m.import_status()[1]
        return {"err": "ok", "msg": _(u"成功"), "status": status}




class FillSizeAndMd5(BaseHandler):
    @js
    @is_admin
    def post(self):
        m = Scanner(self.db, self.settings["ScopedSession"], self.user_id())
        total = m.run_fill_size_and_md5()
        if total == 0:
            return {"err": "empty", "msg": _("没有等待更新的数据！")}
        return {"err": "ok", "msg": _(u"更新成功")}





def routes():
    return [
        (r"/api/admin/scan/list", ScanList),
        (r"/api/admin/scan/run", ScanRun),
        (r"/api/admin/scan/status", ScanStatus),
        (r"/api/admin/scan/delete", ScanDelete),
        (r"/api/admin/scan/mark", ScanMark),
        (r"/api/admin/import/run", ImportRun),
        (r"/api/admin/import/status", ImportStatus),
        (r"/api/admin/import/fsize", UpdateFileSize),
        (r"/api/admin/import/auto", AutoImportRun),
        (r"/api/admin/scan/fillSizeAndMd5", FillSizeAndMd5),
    ]
