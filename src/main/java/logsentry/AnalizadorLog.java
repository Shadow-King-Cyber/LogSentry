package logsentry;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * Analiza un archivo de log línea por línea aplicando reglas de seguridad.
 */
public class AnalizadorLog {
    private final MotorReglas motor;

    public AnalizadorLog(MotorReglas motor) {
        this.motor = motor;
    }

    /**
     * Analiza el archivo indicado y devuelve las alertas encontradas.
     */
    public ResultadoAnalisis analizar(String rutaArchivo, String filtroRegla) throws IOException {
        ResultadoAnalisis resultado = new ResultadoAnalisis(rutaArchivo, 0);
        int numLinea = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(rutaArchivo))) {
            String linea;
            while ((linea = reader.readLine()) != null) {
                numLinea++;
                List<Regla> reglas = motor.obtenerReglas(filtroRegla);

                for (Regla regla : reglas) {
                    if (regla.coincide(linea)) {
                        resultado.agregarAlerta(new Alerta(
                                numLinea,
                                regla.getNivel(),
                                regla.getNombre(),
                                regla.getMensaje(),
                                linea
                        ));
                    }
                }
            }
        }

        return new ResultadoAnalisis(rutaArchivo, numLinea) {{
            for (Alerta a : resultado.getAlertas()) {
                agregarAlerta(a);
            }
        }};
    }
}
