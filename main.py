import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from ttkbootstrap.tooltip import ToolTip
import subprocess
import threading
import re
import ctypes
import sys
import os

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    python_exe = sys.executable if sys.executable.endswith('pythonw.exe') else sys.executable.replace('python.exe', 'pythonw.exe')
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", python_exe, " ".join(sys.argv), None, 1)
    sys.exit()

def get_active_interface():
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in result.stdout.splitlines():
            # بررسی دقیق‌تر برای یافتن رابط فعال
            if "Connected" in line and "Enabled" in line:
                match = re.search(r'Enabled\s+Connected\s+\S+\s+(.+)', line, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        return None
    except Exception as e:
        print(f"Error in get_active_interface: {e}")  # برای دیباگ (در فایل لاگ ذخیره شود)
        return None

dns_servers = {
    "Google DNS": {"ip": "8.8.8.8", "icon": "🌐"},
    "Cloudflare": {"ip": "1.1.1.1", "icon": "☁️"},
    "OpenDNS": {"ip": "208.67.222.222", "icon": "🔒"},
    "radar": {"ip": "10.202.10.10", "icon": "🛡️"},
    "shecan": {"ip": "178.22.122.100", "icon": "🚫"},
    "Electro": {"ip": "78.157.42.100", "icon": "🔒"},
    "Quad9": {"ip": "9.9.9.9", "icon": "🔍"},
    "AdGuard": {"ip": "94.140.14.14", "icon": "🛡️"},
    "DNS.SB": {"ip": "185.222.222.222", "icon": "🔐"},
    "Level3": {"ip": "209.244.0.3", "icon": "🌍"},
}

class DnsSwitcherApp(tb.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("🚀 DNS Switcher Pro")
        self.geometry("800x800")
        self.resizable(False, False)
        self.history = []
        self.ping_results = {}
        self.initial_ping_done = False
        self._create_widgets()
        self._populate_list()
        # شروع به‌روزرسانی وضعیت و پینگ‌ها
        threading.Thread(target=self._start_pinging_all, daemon=True).start()
        threading.Thread(target=self._update_status, daemon=True).start()

    def _create_widgets(self):
        main_frame = tb.Frame(self, bootstyle="dark", padding=20)
        main_frame.pack(fill=BOTH, expand=YES)

        header_frame = tb.Frame(main_frame, bootstyle="primary")
        header_frame.pack(fill=X, pady=(0, 20))
        tb.Label(
            header_frame, text="🌐 DNS Switcher Pro", font=("Segoe UI", 24, "bold"),
            bootstyle="inverse-primary"
        ).pack(pady=10)

        self.status_label = tb.Label(
            header_frame, text="🔄 در حال بررسی وضعیت شبکه...", font=("Segoe UI", 12),
            bootstyle="inverse-light"
        )
        self.status_label.pack(pady=(0, 10))

        self.table_frame = tb.LabelFrame(main_frame, text="📋 انتخاب DNS", bootstyle="info", padding=15)
        self.table_frame.pack(fill=BOTH, expand=YES, pady=10)

        self.canvas = tb.Canvas(self.table_frame, highlightthickness=0)
        self.scrollbar = tb.Scrollbar(self.table_frame, orient=VERTICAL, command=self.canvas.yview)
        self.scrollable_frame = tb.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=LEFT, fill=BOTH, expand=YES)
        self.scrollbar.pack(side=RIGHT, fill=Y)

        self.canvas.bind_all("<MouseWheel>", lambda event: self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units"))

        ctrl_frame = tb.Frame(main_frame, bootstyle="dark", padding=10)
        ctrl_frame.pack(fill=X, pady=10)
        tb.Label(ctrl_frame, text="DNS سفارشی:", font=("Segoe UI", 12), bootstyle="inverse-light").pack(side=LEFT, padx=(0, 10))
        self.custom_entry = tb.Entry(ctrl_frame, width=25, font=("Segoe UI", 12), bootstyle="secondary")
        self.custom_entry.pack(side=LEFT, padx=5)
        ToolTip(self.custom_entry, text="آی‌پی DNS سفارشی را وارد کنید (مثال: 8.8.8.8)")
        self.custom_entry.bind("<KeyRelease>", lambda e: self._validate_ip())

        tb.Button(ctrl_frame, text="تنظیم DNS", bootstyle="success", command=self._set_custom, width=15).pack(side=LEFT, padx=5)
        tb.Button(ctrl_frame, text="بازنشانی", bootstyle="danger", command=self._reset_dns, width=15).pack(side=LEFT, padx=5)

        self.history_label = tb.Label(main_frame, text="آخرین DNS: -", bootstyle="inverse-light")
        self.history_label.pack(pady=10)

    def _populate_list(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        header = tb.Frame(self.scrollable_frame, bootstyle="info")
        header.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 10))
        for idx, text in enumerate(["ارائه‌دهنده", "آی‌پی", "پینگ", "عملیات"]):
            lbl = tb.Label(
                header, text=text,
                font=("Segoe UI", 12, "bold"),
                bootstyle="inverse-info",
                anchor="center", justify="center"
            )
            lbl.grid(row=0, column=idx, padx=60, pady=5, sticky="nsew")
            header.grid_columnconfigure(idx, weight=1)

        self.rows = []
        def ping_key(item):
            ip = item[1]["ip"]
            val = self.ping_results.get(ip)
            if val is None or val == "در حال بررسی...":
                return (2, float('inf'))
            if val in ("Timeout", "خطا"):
                return (3, float('inf'))
            try:
                return (1, int(val))
            except:
                return (3, float('inf'))

        sorted_dns = sorted(dns_servers.items(), key=ping_key)

        for idx, (name, data) in enumerate(sorted_dns, start=1):
            ip = data["ip"]
            icon = data["icon"]
            row = tb.Frame(self.scrollable_frame, bootstyle="dark", padding=5)
            row.grid(row=idx, column=0, columnspan=4, sticky="ew", pady=2)

            for col in range(4):
                row.grid_columnconfigure(col, weight=1)

            tb.Label(row, text=f"{icon} {name}", font=("Segoe UI", 12), anchor="center", justify="center").grid(row=0, column=0, padx=10, sticky="nsew")
            tb.Label(row, text=ip, font=("Segoe UI", 12), bootstyle="inverse-light", anchor="center", justify="center").grid(row=0, column=1, padx=5, sticky="nsew")

            ping_text = self.ping_results.get(ip, "در حال بررسی...")
            style = "warning"
            try:
                ping_val = int(ping_text)
                style = "success"
                ping_text = f"{ping_val} ms"
            except:
                if ping_text in ("Timeout", "خطا"):
                    style = "danger"
                elif ping_text == "در حال بررسی...":
                    style = "warning"

            ping_label = tb.Label(row, text=ping_text, font=("Segoe UI", 12), bootstyle=style, anchor="center", justify="center")
            ping_label.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")

            action_btn = tb.Button(row, text="تغییر", bootstyle="success-outline", command=lambda ip=ip: self._set_dns_thread(ip), width=10)
            action_btn.grid(row=0, column=3, padx=10, pady=5, sticky="nsew")
            ToolTip(action_btn, text=f"تغییر DNS به {name}")
            action_btn.bind("<Enter>", lambda e: e.widget.configure(bootstyle="success"))
            action_btn.bind("<Leave>", lambda e: e.widget.configure(bootstyle="success-outline"))

            self.rows.append((ip, ping_label))

    def _update_status(self):
        iface = get_active_interface()
        if iface:
            status = f"✅ رابط فعال: {iface}"
        else:
            status = "❌ هیچ رابط شبکه‌ای یافت نشد"
        self.status_label.config(text=status)
        self.after(30000, self._update_status)

    def _ping(self, ip):
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "1000", ip],
                capture_output=True, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW
            )
            match = re.search(r"(?:زمان|time)[=<](\d+)ms", result.stdout, re.IGNORECASE)
            if match:
                return match.group(1)
            elif "Destination host unreachable" in result.stdout or "Request timed out" in result.stdout:
                return "Timeout"
            else:
                return "خطا"
        except Exception as e:
            print(f"Error in ping {ip}: {e}")  # برای دیباگ
            return "خطا"

    def _ping_all(self):
        for ip, label in self.rows:
            ping_result = self._ping(ip)
            self.ping_results[ip] = ping_result
            self.after(0, lambda lbl=label, pr=ping_result: lbl.config(text=pr if pr in ("Timeout", "خطا") else f"{pr} ms"))
        self.after(0, self._populate_list)
        self.after(60000, self._ping_all)

    def _start_pinging_all(self):
        for name, data in dns_servers.items():
            ip = data["ip"]
            self.ping_results[ip] = self._ping(ip)
        self.initial_ping_done = True
        self._populate_list()
        threading.Thread(target=self._ping_all, daemon=True).start()

    def _validate_ip(self):
        ip = self.custom_entry.get()
        if re.match(r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$", ip):
            self.custom_entry.configure(bootstyle="success")
        else:
            self.custom_entry.configure(bootstyle="danger")

    def _set_custom(self):
        ip = self.custom_entry.get()
        if not ip:
            Messagebox.show_error("لطفاً آی‌پی DNS را وارد کنید!", title="خطا")
            return
        if not re.match(r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$", ip):
            Messagebox.show_error("فرمت آی‌پی معتبر نیست!", title="خطا")
            return
        self._set_dns_thread(ip)

    def _set_dns_thread(self, ip):
        iface = get_active_interface()
        if not iface:
            Messagebox.show_error('رابط شبکه فعالی یافت نشد!', title="خطا")
            return

        wait_window = tb.Toplevel(self)
        wait_window.title("لطفاً صبر کنید")
        wait_window.geometry("300x100")
        tb.Label(wait_window, text=f"در حال تنظیم DNS به {ip}...", font=("Segoe UI", 12)).pack(pady=20)
        wait_window.transient(self)
        wait_window.grab_set()

        def set_dns():
            try:
                subprocess.run([
                    "netsh", "interface", "ip", "set", "dns", f"name={iface}",
                    "static", ip, "primary"
                ], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.history.append(ip)
                self.after(0, lambda: self.history_label.config(text=f"آخرین DNS: {ip}"))
                self.after(0, lambda: Messagebox.show_info(f"DNS با موفقیت به {ip} تغییر یافت!", title="موفقیت"))
                self.after(0, self._populate_list)
            except subprocess.CalledProcessError:
                self.after(0, lambda: Messagebox.show_error("خطا در تنظیم DNS!", title="خطا"))
            finally:
                self.after(0, wait_window.destroy)

        threading.Thread(target=set_dns, daemon=True).start()
        wait_window.wait_window()

    def _reset_dns(self):
        iface = get_active_interface()
        if not iface:
            Messagebox.show_error("رابط شبکه فعالی یافت نشد!", title="خطا")
            return

        wait_window = tb.Toplevel(self)
        wait_window.title("لطفاً صبر کنید")
        wait_window.geometry("300x100")
        tb.Label(wait_window, text="در حال بازنشانی DNS...", font=("Segoe UI", 12)).pack(pady=20)
        wait_window.transient(self)
        wait_window.grab_set()

        def reset():
            try:
                subprocess.run([
                    "netsh", "interface", "ip", "set", "dns", f"name={iface}",
                    "dhcp"
                ], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.after(0, lambda: Messagebox.show_info("DNS به حالت خودکار بازنشانی شد.", title="موفقیت"))
                self.history.append("خودکار")
                self.after(0, lambda: self.history_label.config(text="آخرین DNS: خودکار"))
                self.after(0, self._populate_list)
            except subprocess.CalledProcessError:
                self.after(0, lambda: Messagebox.show_error("خطا در بازنشانی DNS!", title="خطا"))
            finally:
                self.after(0, wait_window.destroy)

        threading.Thread(target=reset, daemon=True).start()
        wait_window.wait_window()

if __name__ == "__main__":
    app = DnsSwitcherApp()
    app.mainloop()