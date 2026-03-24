import sys
from app import SecureClientApp


def main():
    """
    The main entry point of the Secure File Communication client.
    It initializes the SecureClientApp and handles top-level interruptions.
    """
    try:
        # Initialize and run the main application logic
        client_app = SecureClientApp()
        client_app.run()

    except KeyboardInterrupt:
        # Handle the user forcefully closing the app (e.g., Ctrl+C) gracefully
        print("\n[INFO] Application terminated by the user. Exiting.")
        sys.exit(0)

    except Exception as e:
        # Catch any completely unhandled exceptions that bubbled up to the top
        print(f"\n[FATAL ERROR] An unexpected system error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
