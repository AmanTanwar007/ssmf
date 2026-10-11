.PHONY: install test eval run demo lint
install:
	pip install -r requirements-dev.txt
test:
	python -m pytest tests -q
eval:
	python tools/evaluate.py
run:
	uvicorn ssmf.api:create_app --factory --port 8000
demo:
	python tools/local_demo.py --with-monitor
lint:
	ruff check --select E,F,W --ignore E501 .
