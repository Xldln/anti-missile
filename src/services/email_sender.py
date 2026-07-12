"""邮件发送工具 — 通过 SMTP 发送告警邮件。"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import List
import yaml


def _load_config():
    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def send_alert(subject: str, body: str):
    """发送邮件给 remind-emails 列表中的所有人。"""
    config = _load_config()
    smtp = config.get("smtp", {})
    recipients: List[str] = config.get("remind-emails", [])

    if not recipients:
        return

    msg = MIMEMultipart()
    msg["From"] = smtp.get("user", "")
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    port = smtp.get("port", 465)
    if smtp.get("use_ssl", True):
        server = smtplib.SMTP_SSL(smtp["host"], port)
    else:
        server = smtplib.SMTP(smtp["host"], port)
        server.starttls()

    try:
        server.login(smtp["user"], smtp.get("password", ""))
        server.sendmail(smtp["user"], recipients, msg.as_string())
    finally:
        server.quit()
