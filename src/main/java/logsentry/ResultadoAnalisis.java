package logsentry;

import java.util.ArrayList;
import java.util.List;

/**
 * Almacena los resultados del análisis de logs.
 */
public class ResultadoAnalisis {
    private final String archivo;
    private final int totalLineas;
    private final List<Alerta> alertas;

    public ResultadoAnalisis(String archivo, int totalLineas) {
        this.archivo = archivo;
        this.totalLineas = totalLineas;
        this.alertas = new ArrayList<>();
    }

    public void agregarAlerta(Alerta alerta) {
        alertas.add(alerta);
    }

    public String getArchivo() { return archivo; }
    public int getTotalLineas() { return totalLineas; }
    public List<Alerta> getAlertas() { return alertas; }

    public long contarPorNivel(String nivel) {
        return alertas.stream().filter(a -> a.getNivel().equals(nivel)).count();
    }
}
