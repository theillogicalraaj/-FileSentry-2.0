.PHONY: backend-test run-api docker-up demo
backend-test:
	cd backend && PYTHONPATH=. pytest -q
run-api:
	cd backend && uvicorn app.main:app --reload

docker-up:
	docker compose up --build

demo:
	python scripts/make_demo_samples.py
