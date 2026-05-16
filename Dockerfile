FROM apify/actor-python:3.12

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && rm -rf /root/.cache/pip

COPY . ./
CMD ["python", "-m", "src"]
