test:
	uvx coverage erase
	uvx --with tox-uv tox
	uvx coverage html
