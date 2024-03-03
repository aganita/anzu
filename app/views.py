from flask import Blueprint, render_template
from app.models import detect_devices, read_suricata_alerts

app_views = Blueprint('app_views', __name__, template_folder='../templates')

@app_views.route('/')
def home():
    return render_template('index.html')

@app_views.route('/devices')
def show_devices():
    devices = detect_devices()
    return render_template('devices.html', devices=devices)

@app_views.route('/alerts')
def show_alerts():
    alerts = read_suricata_alerts()
    return render_template('alerts.html', alerts=alerts)




