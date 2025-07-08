import platform
import subprocess

def notify_user(title: str, message: str):
    if platform.system() == "Windows":
        from win10toast import ToastNotifier
        ToastNotifier().show_toast(title, message, duration=5)
    elif platform.system() == "Linux":
        subprocess.run(['notify-send', title, message])
    else:
        print(f"[NOTIFY] {title}: {message}")
