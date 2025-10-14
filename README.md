# Informe de Seguridad (PowerShell)

**Nombre del script:** diagnostico-seguridad-windows
**Propósito:** Recolectar información de diagnóstico en Windows 11 y generar un paquete de evidencia legible (TXT + ZIP) para análisis de seguridad/soporte técnico.

---

## Qué hace
Este script recopila información relevante del sistema (procesos, servicios, tareas programadas, conexiones de red, drivers, hosts, SFC/DISM, firewall, usuarios, eventos de inicio de sesión) y genera:

- Carpeta de salida: `C:\Informe_de_Seguridad\SecurityCheck_YYYYMMDD_HHMMSS\`  
- Archivos individuales (`processes.txt`, `netstat.txt`, `services.txt`, ...).  
- `SecurityReport.txt` con todo el detalle.  
- `Resumen.txt` con un análisis rápido y semáforos de anomalías.  
- Archivo comprimido `.zip` listo para adjuntar o enviar.
- Se puede evaluar cada Txt individualmente o bien darle los informes a un IA para que genere una evaluacion


##Ejecucion

Pegar el contenido el powershell en modo administador

**No realiza  ni modifica configuraciones críticas.**