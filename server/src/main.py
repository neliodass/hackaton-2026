import logging

from cli import interactive_menu

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | update-server | %(message)s",
)


def main() -> None:
    interactive_menu()


if __name__ == "__main__":
    main()
