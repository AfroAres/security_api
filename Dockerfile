# Imagen base oficial de Python
FROM python:3.11-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar archivo de dependencias e instalarlas
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Instalar herramientas necesarias (Nmap, DNS utils, compiladores opcionales)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap dnsutils build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copiar el resto del proyecto
COPY . .

# Variables de entorno
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Exponer el puerto en el que corre Django
EXPOSE 8000

# Script de entrada para migraciones y servidor
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]

# Comando por defecto para ejecutar el servidor de desarrollo
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]