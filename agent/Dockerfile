# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables for the API endpoint and interface name
ENV AFT_API_URL=""
ENV AFT_NET_IFACE=""

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install netifaces requests


# Run Agent.py when the container launches
ENTRYPOINT ["python", "agent.py"]