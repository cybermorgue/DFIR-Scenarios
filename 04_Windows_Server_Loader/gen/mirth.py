"""mirth.log y mirth.properties de Mirth Connect 4.4.0 en int01.

El formato de línea es el de log4j que usa Mirth. Las trazas del 04/10 son una reconstrucción verosímil a partir de
la descripción pública de CVE-2023-43208 (POST /api/users con X-Requested-With: OpenAPI; la deserialización XML
de XStream ocurre antes de la autenticación); no contienen carga alguna.
"""
import random

from .const import OP_IP, TRIAGE_T
from .kape import is_dst
from .winfmt import ft2dt, sec

BUILT = "September 14, 2023"


def _ln(ft, level, thread, logger, msg):
    """Línea de log4j en la hora local del servidor (CEST): la JVM no escribe en UTC."""
    d = ft2dt(ft + (sec(7200) if is_dst(ft) else sec(3600)))
    return f"{level:<5} {d.strftime('%Y-%m-%d %H:%M:%S')},{d.microsecond // 1000:03d} [{thread}] {logger}: {msg}"


def _trace(ft, thread):
    return "\n".join([
        _ln(ft, "ERROR", thread, "com.mirth.connect.server.api.providers.XmlMessageBodyReader",
            "Unable to deserialize request body (POST /api/users)"),
        "com.thoughtworks.xstream.converters.ConversionException: Cannot convert the XML document to the requested type",
        "---- Debugging information ----",
        "message             : Cannot convert the XML document to the requested type",
        "cause-exception     : com.thoughtworks.xstream.converters.ConversionException",
        "class               : com.mirth.connect.model.User",
        "required-type       : com.mirth.connect.model.User",
        "converter-type      : com.thoughtworks.xstream.converters.reflection.ReflectionConverter",
        "line number         : 1",
        "version             : 1.4.19",
        "-------------------------------",
        "\tat com.thoughtworks.xstream.core.TreeUnmarshaller.convert(TreeUnmarshaller.java:79)",
        "\tat com.thoughtworks.xstream.core.TreeUnmarshaller.start(TreeUnmarshaller.java:65)",
        "\tat com.mirth.connect.donkey.util.xstream.XStreamSerializer.deserialize(XStreamSerializer.java:112)",
        "\tat com.mirth.connect.server.api.providers.XmlMessageBodyReader.readFrom(XmlMessageBodyReader.java:61)",
        "\tat org.glassfish.jersey.message.internal.ReaderInterceptorExecutor.invokeReadFrom(ReaderInterceptorExecutor.java:257)",
        "\tat org.glassfish.jersey.servlet.ServletContainer.service(ServletContainer.java:388)",
        "\tat org.eclipse.jetty.server.handler.HandlerWrapper.handle(HandlerWrapper.java:127)",
        "\tat java.base/java.lang.Thread.run(Unknown Source)"])


def mirth_entries(sim):
    """[(ft, texto)] ordenado y cortado en el triage; mirth_log lo junta y la rotación se hace por ft."""
    rng = random.Random(4404)
    ev = []
    for b in sim.boots:
        t = b["t"] + sec(41.0)
        ev += [(t, _ln(t, "INFO", "Main Server Thread", "com.mirth.connect.server.Mirth",
                       f"Mirth Connect 4.4.0 (Built on {BUILT}) server successfully started.")),
               (t - sec(9.0), _ln(t - sec(9.0), "INFO", "Main Server Thread", "com.mirth.connect.server.Mirth",
                                  "Starting Mirth Connect 4.4.0 on Windows Server 2019 (amd64, Java 17.0.8)"))]
    # avisos esporádicos de canal (ACK tardío del emisor)
    t = sim.boots[0]["t"] + sec(3 * 86400)
    while t < TRIAGE_T:
        ev.append((t, _ln(t, "WARN", f"pool-{rng.randint(8, 14)}-thread-{rng.randint(1, 6)}",
                          "com.mirth.connect.connectors.tcp.TcpReceiver",
                          "[ADT_Ardeal] Connection reset by peer while sending ACK")))
        t += sec(rng.uniform(2, 9) * 86400)
    # 04/10: huella de versión y órdenes recibidas por la API (las ve fw01 como peticiones a :8443 desde el operador)
    for c in sorted((c for c in sim.net_log if c.src == OP_IP and c.dport == 8443), key=lambda c: c.start):
        th = f"qtp{rng.randint(10**8, 2 * 10**9)}-{rng.randint(20, 60)}"
        if c.bytes_out < 1000:
            ev.append((c.start, _ln(c.start, "INFO", th, "com.mirth.connect.server.api.servlets.SystemServlet",
                                    f"GET /api/server/version from {OP_IP} (X-Requested-With: OpenAPI)")))
        else:
            t = c.start + sec(0.8)      # la orden ya se ha lanzado cuando falla la conversión
            ev.append((t, _trace(t, th)))
    ev.sort(key=lambda e: e[0])
    return [e for e in ev if e[0] <= TRIAGE_T]


def mirth_log(sim):
    return "\n".join(t for _, t in mirth_entries(sim)) + "\n"


def mirth_properties():
    return """# Mirth Connect 4.4.0 - mirth.properties
dir.appdata = appdata
dir.tempdata = ${dir.appdata}/temp

http.port = 8080
https.port = 8443
http.contextpath = /
server.api.allowhttp = false

https.client.protocols = TLSv1.3,TLSv1.2
https.server.protocols = TLSv1.3,TLSv1.2,SSLv2Hello

keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = Kb!int01-2023
keystore.keypass = Kb!int01-2023
keystore.type = JCEKS

database = derby
database.url = jdbc:derby:${dir.appdata}/mirthdb;create=true
database.max-connections = 20

configurationmap.path = ${dir.appdata}/configuration.properties
"""
