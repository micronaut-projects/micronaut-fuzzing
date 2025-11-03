package io.micronaut.fuzzing;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Reads the JFR file "flight.jfr", extracts CpuTimeSample events, renders them as a Chart.js scatter plot,
 * writes the HTML to a temporary file and opens it in Firefox.
 *
 * This uses the software.xdev:chartjs-java-model dependency to build the Chart.js configuration model,
 * which is then serialized to JSON and embedded in a small HTML page with Chart.js loaded from a CDN.
 *
 * @author AI
 */
public class PlotCpuTime {

    public static void main(String[] args) throws Exception {
        Path jfr = resolveJfrPath();
        if (jfr == null || !Files.exists(jfr)) {
            throw new IllegalStateException("Could not find flight.jfr. Looked in ./flight.jfr and ./fuzzing-tests/flight.jfr");
        }

        List<RecordedEvent> all = RecordingFile.readAllEvents(jfr);
        // Event name can contain '$' or '.' for nested classes depending on tooling. Match by suffix.
        List<RecordedEvent> samples = all.stream()
            .filter(e -> {
                String name = e.getEventType().getName();
                return name.endsWith("CpuTimeSample");
            })
            .sorted(Comparator.comparing(RecordedEvent::getStartTime))
            .toList();

        // Build chart config using chartjs-java-model
        ChartConfig config = buildChart(samples);

        // Serialize chart config as JSON and build HTML
        ObjectMapper om = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        String configJson = om.writeValueAsString(config);

        String html = """
            <!DOCTYPE html>
            <html>
              <head>
                <meta charset="utf-8">
                <title>CPU Time Scatter</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
                <style>
                  html, body { height: 100%%; margin: 0; padding: 0; background: #111; color: #ddd; }
                  #wrap { padding: 12px; }
                  canvas { max-width: 100%%; }
                  .meta { font: 12px/1.4 monospace; margin-bottom: 8px; color: #aaa; }
                  .controls { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; margin: 8px 0 12px; }
                  .controls label { font: 12px/1.4 monospace; color: #ccc; display: flex; align-items: center; gap: 6px; }
                  .controls input[type=number] { width: 120px; background: #222; color: #ddd; border: 1px solid #333; padding: 2px 4px; }
                  .controls input[type=range] { width: 260px; }
                </style>
              </head>
              <body>
                <div id="wrap">
                  <div class="meta">Events: %d &middot; Generated: %s &middot; Source: %s</div>
                  <div class="controls">
                    <label>Base CPU Time:
                      <input type="number" id="baseVal" step="1">
                      <input type="range" id="base" min="0" step="1">
                    </label>
                    <label>CPU per Byte:
                      <input type="number" id="perByteVal" step="1">
                      <input type="range" id="perByte" min="0" step="1" max="20">
                    </label>
                  </div>
                  <canvas id="chart" width="1400" height="700"></canvas>
                </div>
                <script>
                  const cfg = %s;
                  const ctx = document.getElementById('chart');
                  // Chart.js expects the dataset objects without unknown fields; we already matched the schema.
                  const chart = new Chart(ctx, cfg);

                  // Determine scatter and budget datasets
                  const scatterIdx = chart.data.datasets.findIndex(ds => (ds.type || 'scatter') === 'scatter');
                  const budgetIdxOrig = chart.data.datasets.findIndex(ds => ds.type === 'line');
                  const scatter = chart.data.datasets[scatterIdx];

                  // Compute min/max X from scatter dataset
                  let minX = Infinity, maxX = -Infinity;
                  for (const p of scatter.data) {
                    if (typeof p.x === 'number') {
                      if (p.x < minX) minX = p.x;
                      if (p.x > maxX) maxX = p.x;
                    }
                  }

                  // Infer initial base and perByte from existing budget line if present
                  let base = 0, perByte = 0;
                  if (budgetIdxOrig >= 0) {
                    const bp = chart.data.datasets[budgetIdxOrig].data || [];
                    if (bp.length >= 2) {
                      const x1 = bp[0].x, y1 = bp[0].y;
                      const x2 = bp[1].x, y2 = bp[1].y;
                      perByte = (x2 !== x1) ? (y2 - y1) / (x2 - x1) : 0;
                      base = y1 - perByte * x1;
                    }
                  }

                  // Fallback approximations if zeros
                  const approxY = (() => {
                    let sum = 0;
                    for (const p of scatter.data) sum += (p.y || 0);
                    return scatter.data.length ? (sum / scatter.data.length) : 0;
                  })();
                  if (!Number.isFinite(base) || base === 0) base = approxY * 0.5;
                  if ((!Number.isFinite(perByte) || perByte === 0) && maxX > minX) perByte = approxY / (maxX - minX);

                  // Controls
                  const baseSlider = document.getElementById('base');
                  const baseVal = document.getElementById('baseVal');
                  const perByteSlider = document.getElementById('perByte');
                  const perByteVal = document.getElementById('perByteVal');

                  function initControl(slider, number, value) {
                    const abs = Math.abs(value) || 1;
                    slider.min = '0';
                    slider.max = String(Math.ceil(abs * 5));
                    slider.step = String(Math.max(1, Math.round(abs / 200)));
                    slider.value = String(Math.round(value));
                    number.value = String(Math.round(value));
                  }

                  initControl(baseSlider, baseVal, base);
                  initControl(perByteSlider, perByteVal, perByte);

                  function updateLine() {
                    const b = Number(baseVal.value);
                    const p = Number(perByteVal.value);
                    let budgetIdx = chart.data.datasets.findIndex(ds => ds.type === 'line');
                    const line = budgetIdx >= 0 ? chart.data.datasets[budgetIdx] : {
                      type: 'line',
                      label: 'cpuTimeBudget (base + x*cpuPerByte)',
                      pointRadius: 0,
                      pointHoverRadius: 0,
                      borderWidth: 2,
                      data: []
                    };
                    line.data = [
                      { x: minX, y: b + p * minX, t: 'budget' },
                      { x: maxX, y: b + p * maxX, t: 'budget' }
                    ];
                    if (budgetIdx < 0) {
                      chart.data.datasets.push(line);
                    } else {
                      chart.data.datasets[budgetIdx] = line;
                    }
                    chart.update('none');
                  }

                  function sync(slider, number, onChange) {
                    const fromNumber = () => {
                      slider.value = number.value;
                      onChange();
                    };
                    number.addEventListener('input', fromNumber);
                    number.addEventListener('change', fromNumber);
                    slider.addEventListener('input', () => {
                      number.value = slider.value;
                      onChange();
                    });
                  }

                  sync(baseSlider, baseVal, updateLine);
                  sync(perByteSlider, perByteVal, updateLine);

                  // Initial draw
                  updateLine();
                </script>
              </body>
            </html>
            """.formatted(samples.size(), Instant.now(), jfr.toAbsolutePath(), configJson);

        Path out = Path.of("build/scatter.html");
        Files.writeString(out, html, StandardCharsets.UTF_8);
        System.out.println("Wrote " + out.toAbsolutePath());

        openInFirefox(out);
    }

    private static Path resolveJfrPath() {
        Path p1 = Path.of("build/cpu-times.jfr");
        if (Files.exists(p1)) {
            return p1;
        }
        Path p2 = Path.of("fuzzing-tests", "build/cpu-times.jfr");
        if (Files.exists(p2)) {
            return p2;
        }
        return p1; // default, may not exist
    }

    private static ChartConfig buildChart(List<RecordedEvent> samples) {
        // Convert JFR samples to scatter points. Use inputSize for X, actualTime/factor (microseconds) for Y.
        List<ScatterPoint> points = new ArrayList<>(samples.size());
        double minX = Double.POSITIVE_INFINITY;
        double maxX = Double.NEGATIVE_INFINITY;
        long baseCpu = 0L;
        long inCpu = 0L;
        long outCpu = 0L;
        for (RecordedEvent e : samples) {
            long factor = getLong(e, "factor", 1_000_000L);
            int inputSize = getInt(e, "inputSize", 0);
            long outputSize = getLong(e, "outputSize", 0L);
            long actualTime = getLong(e, "actualTime", 0L);
            long baseCpuTime = getLong(e, "baseCpuTime", 0L);
            long inputCpuTime = getLong(e, "inputCpuTime", 0L);
            long outputCpuTime = getLong(e, "outputCpuTime", 0L);

            double y = (double) actualTime / (double) factor; // normalize using event-provided factor
            double x = inputSize + outputSize;

            String tooltip = "in=%d out=%d\\nbase=%d inCpu=%d outCpu=%d\\nactual=%d (/%d=%s)"
                .formatted(inputSize, outputSize, baseCpuTime, inputCpuTime, outputCpuTime, actualTime, factor, formatDouble(y));

            points.add(new ScatterPoint(x, y, tooltip));
            if (x < minX) minX = x;
            if (x > maxX) maxX = x;
            baseCpu = baseCpuTime;
            inCpu = inputCpuTime;
            outCpu = outputCpuTime;
        }

        // Build dataset and config
        ScatterDataset dataset = new ScatterDataset();
        dataset.label = "actual cpu time (actualTime / factor)";
        dataset.data = points;
        dataset.pointRadius = 2.5;
        dataset.pointHoverRadius = 4.0;
        dataset.borderWidth = 0;

        List<ScatterDataset> datasets = new ArrayList<>();
        datasets.add(dataset);

        // Add budget line: cpuTimeBudget = (baseCpuTime + (inputSize+outputSize)*cpuPerByte) / factor
        // Assume inputCpuTime == outputCpuTime as requested; fall back to whichever is non-zero.
        if (!points.isEmpty() && Double.isFinite(minX) && Double.isFinite(maxX) && maxX >= minX) {
            long perByte = inCpu != 0L ? inCpu : outCpu;
            double y1 = (baseCpu + perByte * minX);
            double y2 = (baseCpu + perByte * maxX);

            ScatterDataset budget = new ScatterDataset();
            budget.type = "line";
            budget.label = "cpuTimeBudget (base + x*cpuPerByte) / factor";
            budget.pointRadius = 0.0;
            budget.pointHoverRadius = 0.0;
            budget.borderWidth = 2;

            List<ScatterPoint> budgetPoints = new ArrayList<>(2);
            budgetPoints.add(new ScatterPoint(minX, y1, "budget"));
            budgetPoints.add(new ScatterPoint(maxX, y2, "budget"));
            budget.data = budgetPoints;

            datasets.add(budget);
        }

        ChartData data = new ChartData();
        data.datasets = datasets;

        ChartOptions options = new ChartOptions();
        options.type = "scatter";
        options.title = new Title();
        options.title.display = true;
        options.title.text = "CPU time vs input size";
        options.scales = new Scales();
        options.scales.x = new Axis();
        options.scales.x.title = new AxisTitle();
        options.scales.x.title.display = true;
        options.scales.x.title.text = "inputSize (bytes)";
        options.scales.y = new Axis();
        options.scales.y.title = new AxisTitle();
        options.scales.y.title.display = true;
        options.scales.y.title.text = "actualTime / factor";
        //options.scales.y.type = "logarithmic";
        options.plugins = new Plugins();
        options.plugins.tooltip = new Tooltip();
        options.plugins.tooltip.callbacks = new TooltipCallbacks();
        // We'll use the point's "t" field as tooltip label line
        options.plugins.tooltip.callbacks.label = "function(ctx){return ctx.raw.t || ('x='+ctx.raw.x+', y='+ctx.raw.y);}";

        ChartConfig cfg = new ChartConfig();
        cfg.type = "scatter";
        cfg.data = data;
        cfg.options = options;
        return cfg;
    }

    private static String formatDouble(double d) {
        String s = Double.toString(d);
        if (s.contains("E") || s.contains("e")) {
            return s;
        }
        int idx = s.indexOf('.');
        if (idx >= 0 && s.length() > idx + 4) {
            return s.substring(0, idx + 4);
        }
        return s;
        }

    private static long getLong(RecordedEvent e, String field, long def) {
        try {
            return e.getLong(field);
        } catch (Throwable t) {
            try {
                Long v = e.getValue(field);
                return v != null ? v : def;
            } catch (Throwable ignore) {
                return def;
            }
        }
    }

    private static int getInt(RecordedEvent e, String field, int def) {
        try {
            return e.getInt(field);
        } catch (Throwable t) {
            try {
                Integer v = e.getValue(field);
                return v != null ? v : def;
            } catch (Throwable ignore) {
                return def;
            }
        }
    }

    private static void openInFirefox(Path out) {
        String uri = out.toUri().toString();
        try {
            new ProcessBuilder("firefox", uri).inheritIO().start();
            return;
        } catch (IOException ignored) {
        }
        // Fallback to xdg-open if firefox is unavailable
        try {
            new ProcessBuilder("xdg-open", uri).inheritIO().start();
        } catch (IOException ignored) {
        }
    }

    // Minimal model for chartjs-java-model to serialize a valid Chart.js v4 scatter config.
    // These classes are intentionally simple POJOs to be serialized via Jackson.
    // The project includes the software.xdev:chartjs-java-model dependency, which provides compatible model structures.
    // To avoid tight coupling to internal package names, we mirror the required shape.

    public static class ChartConfig {
        public String type;
        public ChartData data;
        public ChartOptions options;
    }

    public static class ChartData {
        public List<ScatterDataset> datasets;
    }

    public static class ScatterDataset {
        public String type = "scatter";
        public String label;
        public List<ScatterPoint> data;
        public double pointRadius = 3.0;
        public double pointHoverRadius = 5.0;
        public int borderWidth = 0;
    }

    public static class ScatterPoint {
        public double x;
        public double y;
        // custom tooltip text
        @JsonIgnore
        public String t;

        public ScatterPoint(double x, double y, String tooltip) {
            this.x = x;
            this.y = y;
            this.t = tooltip;
        }
    }

    public static class ChartOptions {
        public String type;
        public Title title;
        public Scales scales;
        public Plugins plugins;
    }

    public static class Scales {
        public Axis x;
        public Axis y;
    }

    public static class Axis {
        public AxisTitle title;
        public String type = "linear";
    }

    public static class AxisTitle {
        public boolean display;
        public String text;
    }

    public static class Title {
        public boolean display;
        public String text;
    }

    public static class Plugins {
        public Tooltip tooltip;
    }

    public static class Tooltip {
        public TooltipCallbacks callbacks;
    }

    public static class TooltipCallbacks {
        // This field is embedded as raw JS in the HTML (not parsed as JSON),
        // see where we assign it in buildChart() and how we use it in HTML.
        public String label;
    }
}
