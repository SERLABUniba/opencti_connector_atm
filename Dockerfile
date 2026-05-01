FROM python:3.11-slim
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# 1. Install dependencies
RUN apt-get update && apt-get install -y \
    libmagic1 \
    git \
    && rm -rf /var/lib/apt/lists/*

# 2. Copying requirements and set workdir
COPY requirements.txt /app/requirements.txt
WORKDIR /app

# 3. Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 4. Create the user Connector_SPACESCHIELD
RUN useradd -m -d /home/Connector_ATM -s /bin/bash Connector_ATM

# 5. Copy the source code and assign ownership to the connector user
COPY --chown=Connector_ATM:Connector_ATM src /app/src

# Copy the json ATM file into image
COPY --chown=Connector_ATM:Connector_ATM data/latest_atm.json /app/data/latest_atm.json
# 7. Start the connector
USER Connector_ATM

CMD ["python3", "src/main.py"]