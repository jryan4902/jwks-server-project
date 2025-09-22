.PHONY: install run test lint format

install:
	pip install -r requirements.txt

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8080

test:
	pytest

lint:
	ruff check .
	black --check .

format:
	black .
