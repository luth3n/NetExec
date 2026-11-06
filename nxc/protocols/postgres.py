import socket

import psycopg
from psycopg import OperationalError

from nxc.connection import connection, highlight
from nxc.logger import NXCAdapter
from nxc.config import process_secret
from nxc.protocols.postgres.proto_args import DEFAULT_CREDS

def _s(val, default="-"):
        """Safely stringify a value for table-formatted logging — handles None,
        ipaddress objects (inet/cidr columns), Decimal, UUID, datetime, etc."""
        return default if val is None else str(val)
    
class postgres(connection):
    def __init__(self, args, db, host):
        self.protocol = "POSTGRES"
        self.remote_version = "Unknown"
        self.admin_privs = False
        self.postgres = False
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
            logged_in = self.login_default_creds() if self.args.default_creds else self.login()
            if logged_in:
                if self.args.module:
                    self.load_modules()
                    self.logger.debug("Calling modules")
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def login_default_creds(self):

        self.logger.debug(f"Trying {len(DEFAULT_CREDS)} built-in default credential pair(s)")
        owned = False
        for username, password in DEFAULT_CREDS:
            if self.try_credentials(None, username, owned, password, "plaintext", None):
                owned = True
                if not self.args.continue_on_success:
                    return True
        return owned

    def create_conn_obj(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.args.postgres_timeout)
            s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            response = s.recv(1)
            if response in (b"S", b"N"):
                self.postgres = True
                self.logger.display("PostgreSQL")
            s.close()
            return True
        except OSError:
            return False

    def plaintext_login(self, username, password):
        self.username = username
        self.password = password
        self.admin_privs = False

        try:
            self.conn = psycopg.connect(
                host=self.host, port=self.port,
                user=username, password=password,
                dbname=self.args.database,
                connect_timeout=self.args.postgres_timeout,
            )
            cur = self.conn.cursor()
            cur.execute("SHOW server_version")
            self.remote_version = cur.fetchone()[0]
            cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            row = cur.fetchone()
            self.admin_privs = bool(row[0]) if row else False
        except OperationalError as e:
            self.logger.fail(f"{username}:{process_secret(password)} {e}")
            return False
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} Error: {e}")
            return False

        host_id = self.db.add_host(self.host, self.port, self.remote_version)
        if host_id is None:
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

    def get_file(self):
        try:
            for remote_path, local_path in self.args.get_file:
                with self.conn.cursor() as curr:
                    curr.execute("SELECT pg_read_binary_file(%s)", (remote_path,))
                    data = curr.fetchone()[0]
                    with open(local_path, "wb") as f:
                        f.write(data)
                    self.logger.success(f"[+] Downloaded: {remote_path} -> {local_path}")
        except Exception as e:
            self.logger.fail(f"Error: {e}")

    def put_file(self):
        try:
            for local_path, remote_path in self.args.put_file:
                with open(local_path, "rb") as f:
                    data = f.read()

                with self.conn.cursor() as curr:
                    oid = curr.execute(
                        "SELECT lo_from_bytea(0, %s)",
                        (data,)
                    ).fetchone()[0]

                    curr.execute(
                        "SELECT lo_export(%s, %s)",
                        (oid, remote_path)
                    )

                    curr.execute(
                        "SELECT lo_unlink(%s)",
                        (oid,)
                    )

                    self.conn.commit()

                self.logger.success(f"[+] Uploaded: {local_path} -> {remote_path}")
        except Exception as e:
            self.logger.fail(f"Error: {e}")


    def users(self):
        query = "SELECT usename, usesuper FROM pg_user"
        try:
            with self.conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as err:
            self.logger.fail(f"Error: {err}")
            if not rows:
                context.log.fail("No users returned")
                return

        self.logger.success(f"Found {len(rows)} user(s)")
        self.logger.highlight(f"{'USERNAME':<25}{'usesuper':<5}")
        for username, usesuper in rows:
            self.logger.highlight(f"{username:<25}{usesuper:<5}")


    def dbs(self):
        query = """
            SELECT
                d.datname,
                pg_catalog.pg_get_userbyid(d.datdba) AS owner,
                pg_catalog.pg_size_pretty(pg_catalog.pg_database_size(d.datname)) AS size,
                d.datistemplate,
                d.datallowconn
            FROM pg_catalog.pg_database d
            ORDER BY d.datname;
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as err:
            self.logger.fail(f"Error: {err}")
            if not rows:
                self.logger.fail("No databases returned")
                return

        self.logger.success(f"Found {len(rows)} database(s)")
        self.logger.highlight(f"{'DATABASE':<25}{'OWNER':<20}{'SIZE':<12}{'TEMPLATE':<10}{'ALLOW CONN'}")

        for datname, owner, size, is_template, allow_conn in rows:
            self.logger.highlight(
                f"{datname:<25}{owner:<20}{size:<12}{'Yes' if is_template else 'No':<10}"
                f"{'Yes' if allow_conn else 'No'}"
            )

    def passwords(self):
        query = """SELECT rolname, rolpassword
                    FROM pg_catalog.pg_authid
                    WHERE rolcanlogin = true
                    AND rolpassword IS NOT NULL;
                """
        try:
            with self.conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as err:
            self.logger.fail(f"Error: {err}")
            if not rows:
                self.logger.fail("Error while querying passwords:")
                return

        self.logger.success(f"Found {len(rows)} password(s)")
        self.logger.highlight(f"{'USERNAME':<25}{'PASS':<50}")

        for username, password in rows:
            self.logger.highlight(f"{username:<25}{password:<50}")




    def sessions(self):
        query = """SELECT usename, client_addr, state, query
                    FROM pg_stat_activity;
                """
        try:
            with self.conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as err:
            self.logger.fail(f"Error: {err}")
            if not rows:
                self.logger.fail("Error while querying sessions:")
                return

        self.logger.success(f"Found {len(rows)} session(s)")
        self.logger.highlight(f"{'USENAME':<25}{'CLIENT_ADDR':<50}{'STATE':<10}{'QUERY':<100}")

        for username, client_addr, state, query in rows:
           self.logger.highlight(f"{_s(username):<25}{_s(client_addr):<50}{_s(state):<10}{_s(query):<100}")







