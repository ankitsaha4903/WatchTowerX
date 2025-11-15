.PHONY: run venv install test docker

venv:
	python3 -m venv .venv

install: venv
	. .venv/bin/activate && pip install -r requirements.txt

run:
	streamlit run app/main.py

test:
	pytest -q

docker:
	docker build -t viruslens .