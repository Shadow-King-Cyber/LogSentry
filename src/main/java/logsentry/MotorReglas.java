package logsentry;

import java.util.ArrayList;
import java.util.List;

/**
 * Motor de reglas de detección — carga y gestiona patrones de amenazas.
 */
public class MotorReglas {
    private final List<Regla> reglas = new ArrayList<>();

    public MotorReglas() {
        cargarReglas();
    }

    /** Carga todas las reglas predefinidas de detección. */
    public void cargarReglas() {
        reglas.add(new Regla(
                "brute-force", "alto",
                "(?i)(failed|invalid)\\s+(password|login|authentication).*(\\d+)\\s+times",
                "Posible ataque de fuerza bruta detectado"
        ));
        reglas.add(new Regla(
                "sql-injection", "critico",
                "(?i)(union\\s+select|or\\s+1=1|drop\\s+table|insert\\s+into|delete\\s+from|'\\s*or\\s*')",
                "Posible intento de SQL Injection detectado"
        ));
        reglas.add(new Regla(
                "xss-attempt", "alto",
                "(?i)(<script|javascript:|onerror=|onload=|alert\\()",
                "Posible intento de XSS detectado"
        ));
        reglas.add(new Regla(
                "path-traversal", "alto",
                "(?i)(\\.\\./|\\.\\.\\\\|%2e%2e|%252e)",
                "Posible intento de path traversal detectado"
        ));
        reglas.add(new Regla(
                "ssh-failed", "medio",
                "(?i)failed\\s+password.*ssh|ssh.*failed\\s+password",
                "Intento de SSH fallido"
        ));
        reglas.add(new Regla(
                "unauthorized", "medio",
                "(?i)401\\s+unauthorized|403\\s+forbidden",
                "Acceso no autorizado detectado"
        ));
        reglas.add(new Regla(
                "suspicious-ua", "bajo",
                "(?i)(curl|wget|python-requests|nikto|sqlmap|nmap)",
                "User-Agent sospechoso detectado"
        ));
        reglas.add(new Regla(
                "port-scan", "medio",
                "(?i)(connection\\s+refused|port\\s+scan|SYN\\s+flood)",
                "Posible escaneo de puertos detectado"
        ));
    }

    /** Retorna reglas filtradas por nombre, o todas si el filtro es "all". */
    public List<Regla> obtenerReglas(String filtro) {
        List<Regla> resultado = new ArrayList<>();
        for (Regla r : reglas) {
            if (filtro.equals("all") || r.getNombre().equals(filtro)) {
                resultado.add(r);
            }
        }
        return resultado;
    }

    public int totalReglas() { return reglas.size(); }
}
