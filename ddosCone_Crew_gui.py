#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ConeCrew - Scapy Lab GUI
Captura pasiva y construccion/inspeccion de paquetes en memoria.

SEGURIDAD:
- No transmite paquetes.
- No realiza flooding ni spoofing.
- El constructor solo crea un paquete para inspeccion.
- Captura unicamente trafico visible desde una interfaz autorizada.

Ejecucion en Kali/Linux:
    sudo python3 ddosCone_Crew_gui.py

Dependencias:
    sudo apt install python3-scapy python3-tk
"""

import csv
import ipaddress
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff, conf
except ImportError as exc:
    raise SystemExit(
        "Scapy no esta instalado. En Kali/Debian: sudo apt install python3-scapy"
    ) from exc


class ConeCrewGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ConeCrew | Scapy Lab Monitor")
        self.root.geometry("1100x720")
        self.root.minsize(850, 560)

        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.capture_thread = None
        self.capture_active = False
        self.rows = []

        self.target_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="8080")
        self.interface_var = tk.StringVar(value=str(conf.iface))
        self.filter_var = tk.StringVar(value="ip")
        self.protocol_var = tk.StringVar(value="TCP")
        self.src_var = tk.StringVar(value="127.0.0.1")
        self.dst_var = tk.StringVar(value="127.0.0.1")
        self.sport_var = tk.StringVar(value="50000")
        self.dport_var = tk.StringVar(value="8080")
        self.status_var = tk.StringVar(value="Detenido")
        self.count_var = tk.StringVar(value="Paquetes observados: 0")

        self.build_ui()
        self.root.after(100, self.process_events)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def build_ui(self):
        header = ttk.Frame(self.root, padding=10)
        header.pack(fill="x")
        ttk.Label(
            header, text="ConeCrew | Scapy Lab Monitor",
            font=("TkDefaultFont", 17, "bold")
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Captura pasiva y constructor de paquetes. No se transmite trafico."
        ).pack(anchor="w")

        args = ttk.LabelFrame(self.root, text="Argumentos / objetivo", padding=10)
        args.pack(fill="x", padx=10, pady=5)
        ttk.Label(args, text="Target IP:").grid(row=0, column=0, sticky="w")
        ttk.Entry(args, textvariable=self.target_var, width=20).grid(
            row=0, column=1, padx=5
        )
        ttk.Label(args, text="Puerto:").grid(row=0, column=2, sticky="w")
        ttk.Entry(args, textvariable=self.port_var, width=8).grid(
            row=0, column=3, padx=5
        )
        ttk.Label(args, text="Interfaz:").grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            args, textvariable=self.interface_var,
            values=list(conf.ifaces.keys()), width=18
        ).grid(row=0, column=5, padx=5)

        capture = ttk.LabelFrame(self.root, text="Captura pasiva Scapy", padding=10)
        capture.pack(fill="x", padx=10, pady=5)
        ttk.Label(capture, text="Filtro BPF:").grid(row=0, column=0, sticky="w")
        ttk.Entry(capture, textvariable=self.filter_var, width=32).grid(
            row=0, column=1, padx=5
        )
        self.start_btn = ttk.Button(
            capture, text="Iniciar captura", command=self.start_capture
        )
        self.start_btn.grid(row=0, column=2, padx=5)
        self.stop_btn = ttk.Button(
            capture, text="Detener", command=self.stop_capture, state="disabled"
        )
        self.stop_btn.grid(row=0, column=3, padx=5)
        ttk.Label(capture, textvariable=self.status_var).grid(
            row=0, column=4, padx=10
        )

        columns = ("time", "src", "dst", "protocol", "summary")
        self.table = ttk.Treeview(
            self.root, columns=columns, show="headings", height=13
        )
        for key, label, width in (
            ("time", "Hora", 85), ("src", "Origen", 160),
            ("dst", "Destino", 160), ("protocol", "Protocolo", 90),
            ("summary", "Resumen", 500)
        ):
            self.table.heading(key, text=label)
            self.table.column(key, width=width, anchor="w")
        self.table.pack(fill="both", expand=True, padx=10, pady=5)

        actions = ttk.Frame(self.root, padding=5)
        actions.pack(fill="x")
        ttk.Label(actions, textvariable=self.count_var).pack(side="left")
        ttk.Button(actions, text="Limpiar", command=self.clear).pack(side="right")
        ttk.Button(actions, text="Exportar CSV", command=self.export_csv).pack(
            side="right", padx=5
        )

        builder = ttk.LabelFrame(
            self.root, text="Constructor / vista previa (no transmite)", padding=10
        )
        builder.pack(fill="x", padx=10, pady=5)
        ttk.Label(builder, text="Protocolo").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            builder, textvariable=self.protocol_var,
            values=("TCP", "UDP", "ICMP"), state="readonly", width=8
        ).grid(row=0, column=1, padx=5)

        fields = (
            ("IP origen", self.src_var), ("IP destino", self.dst_var),
            ("Puerto origen", self.sport_var), ("Puerto destino", self.dport_var)
        )
        for i, (label, variable) in enumerate(fields):
            row, col = 1 + i // 2, (i % 2) * 2
            ttk.Label(builder, text=label).grid(row=row, column=col, sticky="w")
            ttk.Entry(builder, textvariable=variable, width=19).grid(
                row=row, column=col + 1, padx=5, pady=2
            )
        ttk.Button(
            builder, text="Construir y mostrar",
            command=self.preview_packet
        ).grid(row=1, column=4, rowspan=2, padx=10)

    def validate_target(self):
        try:
            target = str(ipaddress.ip_address(self.target_var.get().strip()))
            port = int(self.port_var.get())
        except ValueError as exc:
            raise ValueError("Ingresa una IP y un puerto numerico validos.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("El puerto debe estar entre 1 y 65535.")
        return target, port

    def start_capture(self):
        if self.capture_active:
            return
        try:
            target, port = self.validate_target()
        except ValueError as exc:
            messagebox.showerror("Argumentos invalidos", str(exc))
            return

        interface = self.interface_var.get().strip() or None
        bpf = self.filter_var.get().strip() or "ip"
        self.stop_event.clear()
        self.capture_active = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Capturando (solo lectura)...")
        self.events.put((
            "status",
            f"Captura pasiva iniciada | --target {target} --port {port} "
            f"| interfaz={interface} | filtro={bpf}"
        ))
        self.capture_thread = threading.Thread(
            target=self.capture_worker, args=(interface, bpf), daemon=True
        )
        self.capture_thread.start()

    def capture_worker(self, interface, bpf):
        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=interface, filter=bpf, prn=self.packet_callback,
                    store=False, timeout=1
                )
        except Exception as exc:
            self.events.put(("error", str(exc)))
        finally:
            self.events.put(("stopped", None))

    def packet_callback(self, packet):
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        source = packet[IP].src if IP in packet else "-"
        destination = packet[IP].dst if IP in packet else "-"
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "OTHER"
        self.events.put((
            "packet", (timestamp, source, destination, protocol, packet.summary())
        ))

    def stop_capture(self):
        self.stop_event.set()
        self.stop_btn.configure(state="disabled")
        self.status_var.set("Deteniendo...")

    def preview_packet(self):
        try:
            src = str(ipaddress.ip_address(self.src_var.get().strip()))
            dst = str(ipaddress.ip_address(self.dst_var.get().strip()))
            protocol = self.protocol_var.get()
            packet = IP(src=src, dst=dst)

            if protocol in ("TCP", "UDP"):
                sport, dport = int(self.sport_var.get()), int(self.dport_var.get())
                if not (1 <= sport <= 65535 and 1 <= dport <= 65535):
                    raise ValueError("Los puertos deben estar entre 1 y 65535.")
                if protocol == "TCP":
                    packet = packet / TCP(sport=sport, dport=dport, flags="S")
                else:
                    packet = packet / UDP(sport=sport, dport=dport)
            else:
                packet = packet / ICMP()

            packet = packet / Raw(load=b"ConeCrew lab preview")
            output = (
                "PAQUETE CREADO EN MEMORIA - NO ENVIADO\n\n"
                + packet.summary() + "\n\n" + packet.show(dump=True)
            )
            window = tk.Toplevel(self.root)
            window.title("Vista previa Scapy")
            window.geometry("760x460")
            text = tk.Text(window, wrap="word")
            text.pack(fill="both", expand=True)
            text.insert("1.0", output)
            text.configure(state="disabled")
        except ValueError as exc:
            messagebox.showerror("Datos invalidos", str(exc))

    def process_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "packet":
                    self.rows.append(payload)
                    self.table.insert("", "end", values=payload)
                    self.count_var.set(f"Paquetes observados: {len(self.rows)}")
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "error":
                    self.status_var.set("Error de captura")
                    messagebox.showerror(
                        "Scapy", payload +
                        "\nComprueba permisos, interfaz y filtro BPF."
                    )
                elif kind == "stopped":
                    self.capture_active = False
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.status_var.set("Detenido")
        except queue.Empty:
            pass
        self.root.after(100, self.process_events)

    def clear(self):
        self.rows.clear()
        for item in self.table.get_children():
            self.table.delete(item)
        self.count_var.set("Paquetes observados: 0")

    def export_csv(self):
        if not self.rows:
            messagebox.showinfo("CSV", "No hay registros para exportar.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="conecrew_capture.csv"
        )
        if path:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["hora", "origen", "destino", "protocolo", "resumen"])
                writer.writerows(self.rows)
            messagebox.showinfo("CSV", f"Registros guardados en:\n{path}")

    def close(self):
        self.stop_event.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    ConeCrewGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
