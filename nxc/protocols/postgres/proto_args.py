from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    pg_parser = parser.add_parser("postgres", help="own stuff using PostgreSQL",
                                   parents=parents, formatter_class=DisplayDefaultsNotNone)
    pg_parser.add_argument("--port", type=int, default=5432, help="PostgreSQL port")
    pg_parser.add_argument("--database", default="postgres", help="Target database")
    pg_parser.add_argument("--postgres-timeout", type=int, default=5)
    return parser