# LogSentry

Analizador de logs de seguridad escrito en Java — motor de reglas regex para detección de amenazas.

> **ADVERTENCIA**: Solo para fines educativos. Analiza logs, no genera tráfico de red.

## Características

- **Motor de reglas** con expresiones regulares predefinidas
- **Detección** de: fuerza bruta, SQL Injection, XSS, path traversal, SSH fallidos, user-agents sospechosos
- **Archivos de ejemplo** incluidos para pruebas inmediatas
- **Lenguaje**: Java 17+, Maven
- **Tests** unitarios con JUnit 4

## Aviso Legal

Este proyecto es un analizador de logs educativo. No realiza escaneos de red ni ejecuta ataques. Úsalo para aprender sobre análisis de logs de seguridad.

## Requisitos

- Java 17+
- Maven 3.6+

```bash
git clone https://github.com/Shadow-King-Cyber/LogSentry.git
cd LogSentry
mvn compile
```

## Inicio Rápido

```bash
# Compilar
mvn compile

# Ejecutar con log de autenticación
mvn exec:java -Dexec.args="src/main/resources/sample_auth.log"

# Ejecutar con log web
mvn exec:java -Dexec.args="src/main/resources/sample_web.log"

# Ejecutar solo regla de fuerza bruta
mvn exec:java -Dexec.args="src/main/resources/sample_auth.log brute-force"

# Empaquetar y ejecutar
mvn package
java -jar target/logsentry-1.0.0.jar src/main/resources/sample_auth.log
```

## Reglas de Detección

| Regla | Severidad | Descripción |
|-------|-----------|-------------|
| `brute-force` | Alto | Múltiples intentos de login fallidos |
| `sql-injection` | Crítico | Patrones de SQL Injection (UNION SELECT, OR 1=1, DROP TABLE) |
| `xss-attempt` | Alto | Etiquetas script, event handlers |
| `path-traversal` | Alto | Secuencias `../` o `%2e%2e` |
| `ssh-failed` | Medio | Fallos de autenticación SSH |
| `unauthorized` | Medio | Códigos 401/403 |
| `suspicious-ua` | Bajo | User-Agents: sqlmap, nikto, curl, nmap |
| `port-scan` | Medio | Patrones de escaneo de puertos |

## Estructura del Proyecto

```
LogSentry/
├── pom.xml
├── src/
│   ├── main/
│   │   ├── java/logsentry/
│   │   │   ├── Main.java
│   │   │   ├── AnalizadorLog.java
│   │   │   ├── MotorReglas.java
│   │   │   ├── Regla.java
│   │   │   ├── Alerta.java
│   │   │   └── ResultadoAnalisis.java
│   │   └── resources/
│   │       ├── sample_auth.log
│   │       └── sample_web.log
│   └── test/java/logsentry/
│       └── MotorReglasTest.java
├── .gitignore
├── LICENSE              # Licencia MIT
└── README.md
```

## Ejecutar Tests

```bash
mvn test
```

## Licencia

MIT License — ver [LICENSE](LICENSE)
