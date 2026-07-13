package logsentry;

/**
 * Punto de entrada de LogSentry — Analizador de logs de seguridad.
 */
public class Main {
    public static void main(String[] args) {
        System.out.println("=== LogSentry v1.0.0 ===");
        System.out.println("Analizador de logs de seguridad");
        System.out.println();

        if (args.length < 1) {
            System.out.println("Uso: java -jar logsentry.jar <archivo.log> [regla]");
            System.out.println();
            System.out.println("Archivos de ejemplo:");
            System.out.println("  java -jar logsentry.jar src/main/resources/sample_auth.log brute-force");
            System.out.println("  java -jar logsentry.jar src/main/resources/sample_web.log sql-injection");
            return;
        }

        String archivo = args[0];
        String regla = args.length > 1 ? args[1] : "all";

        try {
            MotorReglas motor = new MotorReglas();
            motor.cargarReglas();

            AnalizadorLog analizador = new AnalizadorLog(motor);
            ResultadoAnalisis resultado = analizador.analizar(archivo, regla);

            System.out.println("[+] Análisis completado:");
            System.out.println("    Archivo:       " + resultado.getArchivo());
            System.out.println("    Líneas:        " + resultado.getTotalLineas());
            System.out.println("    Alertas:       " + resultado.getAlertas().size());
            System.out.println("    Críticas:      " + resultado.contarPorNivel("critico"));
            System.out.println("    Altas:         " + resultado.contarPorNivel("alto"));
            System.out.println("    Medias:        " + resultado.contarPorNivel("medio"));
            System.out.println("    Bajas:         " + resultado.contarPorNivel("bajo"));
            System.out.println();

            for (Alerta alerta : resultado.getAlertas()) {
                System.out.println("  [" + alerta.getNivel().toUpperCase() + "] Línea " +
                        alerta.getLinea() + ": " + alerta.getMensaje());
            }
        } catch (Exception e) {
            System.err.println("[-] Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
