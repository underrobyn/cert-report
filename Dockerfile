FROM python:3.10-bullseye

WORKDIR /src

RUN mkdir -p /src/report

# Install code requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code to container
COPY . .

CMD [ "python3", "/src/checker.py" ]