# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# Using --no-cache-dir to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container at /app
COPY MetasploitMCP.py .

# Make port 8085 available to the world outside this container
# This is the port your Uvicorn server will listen on inside the container.
# You can change this if your script is configured for a different default internal port.
EXPOSE 8085

# Define environment variables with default values (can be overridden at runtime)
# These are placeholders; you MUST provide actual values for MSF_SERVER, MSF_PORT, MSF_PASSWORD at runtime.
ENV MSF_SERVER="127.0.0.1"
ENV MSF_PORT="55553"
ENV MSF_PASSWORD="yourpassword"
ENV MSF_SSL="false"
ENV PAYLOAD_SAVE_DIR="/app/payloads"
ENV LOG_LEVEL="INFO"
ENV TRANSPORT_MODE="http"
# Port for Uvicorn inside the container
ENV LISTEN_PORT="8085"

# Run MetasploitMCP.py when the container launches
# The script uses argparse, so we pass arguments here.
# It will listen on 0.0.0.0 to be accessible from outside the container.
CMD python MetasploitMCP.py --host 0.0.0.0 --port ${LISTEN_PORT} --transport ${TRANSPORT_MODE} 