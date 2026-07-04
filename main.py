from passiveSnooping import init_db, start_in_thread
from app import app
from config import HOST, PORT

if __name__ == "__main__":
    init_db()
    start_in_thread()
    app.run(debug=False, host=HOST, port=PORT)
