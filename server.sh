#! /bin/bash
BASE="$( dirname -- '$0' )"

setup () {
  # return
  mkdir -p "$BASE/run"
  if [ ! -d "$BASE/env" ]; then
    python -m venv "$BASE/env"
    source "$BASE/env/bin/activate"
    "$BASE/env/bin/pip" install -r "$BASE/requirements.txt"
  else
    source "$BASE/env/bin/activate"
  fi
}

caching () {
    memcached -s "$BASE/run/memcached.sock" -P "$BASE/run/memcached.pid" &
}

case $1 in
  "")
    setup
    uwsgi --ini "$BASE/uwsgi.ini"
    ;;
  debug)
    setup
    if which memcached &> /dev/null; then
        caching
    else
        echo "starting server without memcached"
    fi
    cd "$BASE/src/flask_modular_login"
    python -m flask --app server:app run --port 8000 --debug
    ;;
  start)
    setup
    nohup uwsgi --ini "$BASE/uwsgi.ini" > "$BASE/run/nohup.out" &
    ;;
  stop)
    killall uwsgi
    ;;
  setup)
    setup
    ;;
  clean)
    rm -fr "$BASE/run" "$BASE/env"
    ;;
  cleansetup)
    rm -fr "$BASE/env"
    setup
    ;;
  link)
    setup
    echo 'sh "'$BASE'/server.sh" $@' > "$BASE/env/bin/server"
    chmod u+x "$BASE/env/bin/server"
    ;;
  ws)
    setup
    shift
    python "$BASE/src/flask_modular_login/pubsub.py" $@
    ;;
  help | *)
    echo "usage: server.sh [start | stop | help]"
    ;;
esac

