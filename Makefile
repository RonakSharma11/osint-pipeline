.PHONY: venv install test run docker-up

venv:
	python3 -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip

install:
	. .venv/bin/activate && pip install -r requirements.txt

test:
	. .venv/bin/activate && pytest -q

docker-up:
	docker compose up --build
