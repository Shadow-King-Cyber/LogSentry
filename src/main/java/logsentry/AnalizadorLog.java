package logsentry;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;

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

        List<Regla> reglas = motor.obtenerReglas(filtroRegla);

        try (BufferedReader reader = new BufferedReader(new FileReader(rutaArchivo))) {
            String linea;
            while ((linea = reader.readLine()) != null) {
                numLinea++;
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

        ResultadoAnalisis analisis = new ResultadoAnalisis(rutaArchivo, numLinea);
        for (Alerta alerta : resultado.getAlertas()) {
            analisis.agregarAlerta(alerta);
        }
        return analisis;
    }
}
