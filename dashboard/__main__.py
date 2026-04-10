"""Run the Bulwark Dashboard server.

Usage: python -m dashboard [--port PORT] [--host HOST]
"""
import argparse


def main():
    parser = argparse.ArgumentParser(description="Bulwark Dashboard")
    parser.add_argument("--port", type=int, default=3000, help="Port to listen on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()

    import uvicorn
    uvicorn.run("dashboard.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
