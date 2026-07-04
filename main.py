from passiveSnooping import init_db, start_in_thread
from app import app

if __name__ == "__main__":
    init_db()
    start_in_thread()
    app.run(debug=False, port=5000)