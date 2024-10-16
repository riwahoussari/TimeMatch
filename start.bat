@echo off
set PORT=%1
gunicorn app:app --bind 0.0.0.0:%PORT%
