docker run --rm --user "$(id -u)":"$(id -g)" -v "$PWD":/usr/src/tox -w /usr/src/tox rust:1.61.0 cargo build -p examples --example tox_proxy_server
docker run --rm --user "$(id -u)":"$(id -g)" -v "$PWD":/usr/src/tox -w /usr/src/tox rust:1.61.0 cargo build -p examples --example tox_proxy_client
