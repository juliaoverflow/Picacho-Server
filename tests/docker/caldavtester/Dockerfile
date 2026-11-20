# Build context: target/dav-src (holds ccs-pycalendar and ccs-caldavtester clones).
FROM python:2.7-slim
COPY ccs-pycalendar /pycalendar
COPY ccs-caldavtester /cdt
RUN pip install --no-cache-dir /pycalendar && pip install --no-cache-dir -e /cdt --no-deps
WORKDIR /cdt
ENTRYPOINT ["python", "testcaldav.py"]
