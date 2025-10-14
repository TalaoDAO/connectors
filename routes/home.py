from flask import render_template, current_app
import logging
from flask_login import current_user, logout_user
import markdown

logging.basicConfig(level=logging.INFO)


def init_app(app):
    app.add_url_rule('/',  view_func=home, methods=['GET', 'POST'])
    app.add_url_rule('/signin',  view_func=signin, methods = ['GET', 'POST'])
    app.add_url_rule('/pricing',  view_func=pricing, methods = ['GET', 'POST'])
    app.add_url_rule('/logout',  view_func=logout, methods = ['GET', 'POST'])
    app.add_url_rule("/documentation/<page>", view_func=show_markdown_page, methods=['GET'])
    app.add_url_rule('/debug/<debug_mode>',  view_func=debug, methods = ['GET', 'POST'])
    return


def home():
    return render_template("home.html", user=current_user)
    

def pricing():
    return render_template("pricing.html")


def signin():
    mode = current_app.config["MODE"]
    return render_template("register.html", mode=mode, title="Sign-In")

def logout():
    logout_user()
    return render_template("home.html", user=None)


def show_markdown_page(page):
    try:
        with open(f"documentation/{page}.md", "r") as f:
            content = f.read()
    except FileNotFoundError:
        return "Page not found", 404
    html_content = markdown.markdown(content, extensions=["tables", "fenced_code"])
    return render_template("markdown_template.html", page=page, html_content=html_content)


def debug(debug_mode):
    mode = current_app.config["MODE"]
    if debug_mode == "on":
        mode.debug_on()
    else:
        mode.debug_off()
    return render_template("menu.html", user=current_user)
        