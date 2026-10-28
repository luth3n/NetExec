import socket

import psycopg
from psycopg import OperationalError

from nxc.connection import connection, highlight
from nxc.logger import NXCAdapter
from nxc.config import process_secret


class postgres(connection):
    def __init__(self, args, db, host):
        self.protocol = "POSTGRES"
        self.remote_version = "Unknown"
        self.admin_privs = False
        super().__init__(args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(extra={
            "protocol": "POSTGRES",
            "host": self.host,
            "port": self.port,
            "hostname": self.hostname,
        })

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            if self.login():
                if self.args.module:
                    self.load_modules()
                    #self.logger.debug("Calling modules")
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def create_conn_obj(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.args.postgres_timeout)
            s.close()
            return True
        except OSError:
            return False

    def plaintext_login(self, username, password):
        self.username = username
        self.password = password
        # сбрасываем на каждую попытку, иначе флаг "утекает" с предыдущей учётки
        # при переборе нескольких пар логин/пароль на одном объекте connection
        self.admin_privs = False

        try:
            with psycopg.connect(
                host=self.host, port=self.port,
                user=username, password=password,
                dbname=self.args.database,
                connect_timeout=self.args.postgres_timeout,
            ) as conn, conn.cursor() as cur:
                # обе проверки - версия и rolsuper - делаем в одном соединении/курсоре,
                # а не открываем второе подключение, как было в check_if_admin() отдельно
                cur.execute("SHOW server_version")
                self.remote_version = cur.fetchone()[0]

                # current_user - это та роль, которой мы только что залогинились;
                # так безопаснее и логичнее, чем подставлять username в запрос напрямую
                cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                row = cur.fetchone()
                self.admin_privs = bool(row[0]) if row else False

        except OperationalError as e:
            self.logger.fail(f"{username}:{process_secret(password)} {e}")
            return False
        except Exception as e:
            # более широкий except: ловит ошибки прав/протокола внутри самих запросов
            # (InsufficientPrivilege и т.п.), а не только ошибки установления соединения
            self.logger.fail(f"{username}:{process_secret(password)} Error: {e}")
            return False

        # --- запись результатов в БД workspace ---
        host_id = self.db.add_host(self.host, self.port, self.remote_version)
        if host_id is None:
            # add_host() не возвращает id при первой вставке хоста (upsert без RETURNING)
            hosts = self.db.get_hosts(self.host)
            host_id = hosts[0].id if hosts else None
        elif isinstance(host_id, list):
            host_id = host_id[0]

        cred_id = self.db.add_credential("plaintext", username, password)

        if host_id and cred_id:
            self.db.add_loggedin_relation(cred_id, host_id)
            if self.admin_privs:
                self.db.add_admin_user(cred_id, host_id)

        self.logger.success(
            f"{username}:{process_secret(password)} {self.mark_pwned()} "
            f"{highlight(f'PostgreSQL {self.remote_version}')}"
        )
        return True