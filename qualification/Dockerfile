ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY wheels /wheels
COPY requirements.txt /opt/requirements.txt
RUN pip install --no-index --find-links=/wheels --require-hashes -r /opt/requirements.txt && rm -rf /wheels
COPY role.py /opt/role.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/opt/role.py"]
