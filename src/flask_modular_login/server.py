import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from builder import app, LoginCaller
from endpoints import LoginBlueprint

end_locals()

login_config = LoginCaller()
login_required = login_config.login_required
login_optional = login_config.login_optional

auth_bp = LoginBlueprint()
AccessNamespace = auth_bp.group
app.register_blueprint(auth_bp)

if __name__ == "__main__":
    app.run(port=8000)

