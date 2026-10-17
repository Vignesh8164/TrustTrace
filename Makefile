.PHONY: install build format typecheck test run

install:
	npm ci

build:
	npm run build

format:
	npm run format

typecheck:
	npm run typecheck

test:
	npm test

run:
	npm start
