web: gunicorn --bind 0.0.0.0:$PORT run:app --chdir core --workers 2 --threads 16 --worker-class gthread --timeout 60 --keep-alive 5
