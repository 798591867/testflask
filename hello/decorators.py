from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission


# 验证其他用户的各种权限
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 验证管理员的权限
def admin_required(f):
    return permission_required(Permission.ADMIN)(f)