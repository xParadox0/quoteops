import sys

from quoteops.migrate import migrate

USAGE = ("usage: python -m quoteops migrate\n"
         "       python -m quoteops create-admin <email>\n"
         "       python -m quoteops reset-admin <email>\n"
         "The administrator's password is asked on the terminal (or read as one line of stdin),"
         " never given on the command line.")


def main(argv: list[str]) -> int:
    if argv == ["migrate"]:
        migrate()
        print("migrate: schema applied")
        return 0
    # Exactly one argument, the address: a password or any option on the command line would
    # end up in the shell history and the process list, so it is refused.
    if len(argv) == 2 and argv[0] in ("create-admin", "reset-admin") and not argv[1].startswith("-"):
        from quoteops import admin_cli
        return admin_cli.run(argv[0], argv[1])
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
