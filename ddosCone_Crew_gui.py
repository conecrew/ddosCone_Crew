#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ConeCrew - interfaz visual de simulacion.
No utiliza Scapy, no crea sockets y NO envia paquetes ni trafico de red.
Compatible con Google Colab y Jupyter Notebook.
"""

import ipaddress
import random
import threading
import time
from datetime import datetime

import ipywidgets as widgets
from IPython.display import display


# 1. Estado compartido de la simulacion
stop_event = threading.Event()
worker = None
counter = 0


# 2. Controles de la interfaz
target_input = widgets.Text(
    value="127.0.0.1",
    description="Target:",
    placeholder="Ej. 127.0.0.1",
    layout=widgets.Layout(width="420px")
)

port_input = widgets.BoundedIntText(
    value=8080,
    min=1,
    max=65535,
    description="Puerto:",
    layout=widgets.Layout(width="220px")
)

interval_input = widgets.FloatSlider(
    value=1.0,
    min=0.2,
    max=3.0,
    step=0.2,
    description="Intervalo:",
    readout_format=".1f",
    layout=widgets.Layout(width="420px")
)

start_button = widgets.Button(
    description="Iniciar simulacion",
    button_style="success",
    icon="play"
)

stop_button = widgets.Button(
    description="Detener",
    button_style="danger",
    icon="stop",
    disabled=True
)

clear_button = widgets.Button(
    description="Limpiar registro",
    button_style="",
    icon="trash"
)

status = widgets.HTML(
    value="<b>Estado:</b> <span style='color:gray'>Detenido</span>"
)

log = widgets.Output(
    layout=widgets.Layout(
        border="1px solid #888",
        height="300px",
        width="100%",
        overflow_y="auto"
    )
)


# 3. Funcion para escribir mensajes en pantalla
def write_log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    with log:
        print(f"[{timestamp}] {message}")


# 4. Validar los argumentos antes de iniciar
def validate_arguments():
    try:
        target = str(ipaddress.ip_address(target_input.value.strip()))
    except ValueError:
        raise ValueError("El target debe ser una direccion IP valida.")

    port = port_input.value
    if not 1 <= port <= 65535:
        raise ValueError("El puerto debe estar entre 1 y 65535.")

    return target, port


# 5. Generar datos ficticios de demostracion.
# Se usan direcciones reservadas para documentacion.
def simulated_source_ip():
    return f"192.0.2.{random.randint(1, 254)}"


# 6. Bucle de simulacion: solo muestra registros; no envia trafico.
def simulation_loop(target, port):
    global counter

    write_log("SIMULACION iniciada. No se enviara trafico de red.")
    write_log(f"Argumentos: --target {target} --port {port}")

    while not stop_event.is_set():
        counter += 1
        source_ip = simulated_source_ip()
        source_port = random.randint(1024, 65535)

        write_log(
            f"SIMULADO N.P: {counter} | "
            f"TARGET: {target}:{port} | "
            f"IP SRC: {source_ip} | "
            f"SRC PORT: {source_port}"
        )

        stop_event.wait(interval_input.value)

    write_log("Simulacion detenida por el usuario.")


# 7. Accion del boton Iniciar
def on_start_clicked(_):
    global worker, counter

    if worker is not None and worker.is_alive():
        return

    try:
        target, port = validate_arguments()
    except ValueError as error:
        status.value = (
            "<b>Estado:</b> "
            f"<span style='color:red'>{error}</span>"
        )
        return

    counter = 0
    stop_event.clear()

    target_input.disabled = True
    port_input.disabled = True
    start_button.disabled = True
    stop_button.disabled = False

    status.value = (
        "<b>Estado:</b> "
        "<span style='color:green'>Simulando...</span>"
    )

    worker = threading.Thread(
        target=simulation_loop,
        args=(target, port),
        daemon=True
    )
    worker.start()


# 8. Accion del boton Detener
def on_stop_clicked(_):
    stop_event.set()
    stop_button.disabled = True
    status.value = (
        "<b>Estado:</b> "
        "<span style='color:orange'>Deteniendo...</span>"
    )
    target_input.disabled = False
    port_input.disabled = False
    start_button.disabled = False


# 9. Accion del boton Limpiar
def on_clear_clicked(_):
    log.clear_output()


# 10. Conectar eventos de los botones
start_button.on_click(on_start_clicked)
stop_button.on_click(on_stop_clicked)
clear_button.on_click(on_clear_clicked)


# 11. Construir y mostrar la interfaz
header = widgets.HTML(
    value=(
        "<h2>ConeCrew - Monitor de simulacion</h2>"
        "<p>Panel visual para practicar argumentos y registros.</p>"
        "<p><b>Modo seguro:</b> no genera ni transmite paquetes.</p>"
    )
)

controls = widgets.VBox([
    header,
    target_input,
    port_input,
    interval_input,
    widgets.HBox([start_button, stop_button, clear_button]),
    status,
    widgets.HTML("<b>Registro de actividad:</b>"),
    log
])

display(controls)
