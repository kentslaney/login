#! /bin/bash
BASE="$( dirname -- "$0" )"

setup () {
  mkdir -p "$BASE/run"
  if [ ! -d "$BASE/env" ]; then
    python -m venv "$BASE/env"
    source "$BASE/env/bin/activate"
    "$BASE/env/bin/pip" install -r "$BASE/requirements.txt"
  else
    source "$BASE/env/bin/activate"
  fi
}

case $1 in
  "")
    setup
    uwsgi --ini "$BASE/uwsgi.ini"
    ;;
  debug)
    setup
    cd "$BASE/src"
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
  help | *)
    echo "usage: server.sh [start | stop | help]"
    ;;
esac