# -*- coding: utf-8 -*-
"""The app module, containing the app factory function."""
import logging
import os
import sys
import uuid
import yaml
import threading, subprocess, socket

from flask import Flask, render_template

from .suricata import Suricata
from .utils import submit_alert

from anzu import commands, public, user
from anzu.extensions import (
    bcrypt,
    cache,
    csrf_protect,
    db,
    debug_toolbar,
    flask_static_digest,
    login_manager,
    migrate,
)


def create_app(config_object="anzu.settings"):
    """Create application factory, as explained here: http://flask.pocoo.org/docs/patterns/appfactories/.

    :param config_object: The configuration object to use.
    """
    check_root()

    app = Flask(__name__.split(".")[0])
    app.config.from_object(config_object)

    register_extensions(app)
    register_blueprints(app)
    register_errorhandlers(app)
    register_shellcontext(app)
    register_commands(app)
    configure_logger(app)
    
    # only start suricata if we're in prod mode, not build mode
    if 'INBUILD' not in os.environ:
        Suricata().start()
        # thread = threading.Thread(target=listen_to_socket, args=('/tmp/suricata.sock',))
        # thread.daemon = True
        # thread.start()

    return app

def listen_to_socket(socket_path):
    # Check if the socket already exists and remove it if it does
    if os.path.exists(socket_path):
        os.remove(socket_path)

    # Create a new socket using the AF_UNIX address family
    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_socket.bind(socket_path)
    server_socket.listen()

    print("Server is listening on socket:", socket_path)

    try:
        connection, client_address = server_socket.accept()
        print("New connection to sock")

        while True:
            data = connection.recv(4096)
            if data:
                alert = data.decode().strip()
                print("New alert:", alert)
                submit_alert(alert)
            else:
                connection.close()
                print("Connection closed")
                break
    finally:
        connection.close()
        server_socket.close()
        os.remove(socket_path)

def register_extensions(app):
    """Register Flask extensions."""
    bcrypt.init_app(app)
    cache.init_app(app)
    db.init_app(app)
    csrf_protect.init_app(app)
    login_manager.init_app(app)
    debug_toolbar.init_app(app)
    migrate.init_app(app, db)
    flask_static_digest.init_app(app)
    return None


def register_blueprints(app):
    """Register Flask blueprints."""
    app.register_blueprint(public.views.blueprint)
    app.register_blueprint(user.views.blueprint)
    return None


def register_errorhandlers(app):
    """Register error handlers."""

    def render_error(error):
        """Render error template."""
        # If a HTTPException, pull the `code` attribute; default to 500
        error_code = getattr(error, "code", 500)
        return render_template(f"{error_code}.html"), error_code

    for errcode in [401, 404, 500]:
        app.errorhandler(errcode)(render_error)
    return None


def register_shellcontext(app):
    """Register shell context objects."""

    def shell_context():
        """Shell context objects."""
        return {"db": db, "User": user.models.User}

    app.shell_context_processor(shell_context)


def register_commands(app):
    """Register Click commands."""
    app.cli.add_command(commands.test)
    app.cli.add_command(commands.lint)


def configure_logger(app):
    """Configure loggers."""
    handler = logging.StreamHandler(sys.stdout)
    if not app.logger.handlers:
        app.logger.addHandler(handler)

def check_root():
    if os.geteuid() != 0:
        raise EnvironmentError("To manage suricata, this app must be run as root")
