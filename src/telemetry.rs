use std::{sync::{Arc, atomic::{AtomicU64, Ordering}}, time::Instant};

const TARGET_TELEMETRY: &str = "telemetry";

/// Simple metric
pub struct Metric {
    average: AtomicU64,
    counter: AtomicU64,
    current: AtomicU64,
    maximum: AtomicU64,
    totally: Option<AtomicU64>,
    name: String
}

impl Metric {

    /// Constructor
    pub fn with_name(name: &str) -> Arc<Self> {
        Self::construct(name, false)
    }

    /// Constructor
    pub fn with_name_and_total(name: &str) -> Arc<Self> {
        Self::construct(name, true)
    }

    /// Get average value
    pub fn average(&self) -> u64 {
        self.average.load(Ordering::Relaxed)
    }

    /// Get current value
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::Relaxed)
    }

    /// Get maximum value
    pub fn maximum(&self) -> u64 {
        self.maximum.load(Ordering::Relaxed)
    }

    /// Get total value
    pub fn totally(&self) -> Option<u64> {
        self.totally.as_ref().map(|totally| totally.load(Ordering::Relaxed))
    }

    /// Get metric name
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Update metric
    pub fn update(&self, update: u64) {
        // Calculate average with Welford's method
        loop {
            let counter = self.counter.load(Ordering::Relaxed);
            let average = self.average.load(Ordering::Relaxed);
            let update = ((update as i128 - average as i128) / (counter as i128 + 1)) as u64;
            if self.counter.compare_exchange(
                counter, 
                counter + 1, 
                Ordering::Relaxed, 
                Ordering::Relaxed
            ).is_err() {
                continue
            }
            if self.average.compare_exchange(
                average, 
                average + update,  
                Ordering::Relaxed, 
                Ordering::Relaxed
            ).is_err() {
                self.counter.fetch_sub(1, Ordering::Relaxed);
                continue
            }
            break
        }
        // Calculate maximum
        loop {
            let maximum = self.maximum.load(Ordering::Relaxed);
            if maximum < update {
                if self.maximum.compare_exchange(
                    maximum, 
                    update,  
                    Ordering::Relaxed, 
                    Ordering::Relaxed
                ).is_err() {
                    continue
                }
            }
            break
        }
        // Store current
        self.current.store(update, Ordering::Relaxed);
        // Store total
        self.totally.as_ref().map(|totally| totally.fetch_add(update, Ordering::Relaxed));
    }

    fn construct(name: &str, with_total: bool) -> Arc<Self> {
        let ret = Self {
            average: AtomicU64::new(0),
            counter: AtomicU64::new(0),
            current: AtomicU64::new(0),
            maximum: AtomicU64::new(0),
            totally: if with_total {
                Some(AtomicU64::new(0))
            } else {
                None
            },
            name: format!("{}:", name)
        };
        Arc::new(ret)
    }

}

/// Metric measured per period
pub struct MetricBuilder {
    last: AtomicU64,
    metric: Arc<Metric>,
    period_nanos: u64, 
    start: Instant,
    value: AtomicU64
}

impl MetricBuilder {

    /// Constructor
    pub fn with_metric_and_period(metric: Arc<Metric>, period_nanos: u64) -> Arc<Self> {
        let ret = Self {
            last: AtomicU64::new(0),
            metric,
            period_nanos: if period_nanos < 1 {
                0
            } else {
                period_nanos
            },
            start: Instant::now(),
            value: AtomicU64::new(0)
        };
        Arc::new(ret)
    }

    /// Get metric
    pub fn metric(&self) -> &Arc<Metric> {
        &self.metric
    }

    /// Update value 
    pub fn update(&self, update: u64) {
        loop {
            let elapsed = self.start.elapsed().as_nanos() as u64;
            let mut last = self.last.load(Ordering::Relaxed);
            if elapsed >= last + self.period_nanos {
                if self.last.compare_exchange(
                    last, 
                    elapsed,
                    Ordering::Relaxed,
                    Ordering::Relaxed
                ).is_err() {
                    continue
                }
                loop {
                    last += self.period_nanos;     
                    if last > elapsed {
                        break
                    }
                    self.metric.update(0);
                }
                self.metric.update(self.value.swap(update, Ordering::Relaxed));
            } else if elapsed >= last {
                self.value.fetch_add(update, Ordering::Relaxed);
            } else {
                if self.last.compare_exchange(
                    last, 
                    elapsed,
                    Ordering::Relaxed,
                    Ordering::Relaxed
                ).is_err() {
                    continue
                }
                self.value.store(update, Ordering::Relaxed);
            }
            break          
        }
    }

    fn refresh(&self) {
        let elapsed = self.start.elapsed().as_nanos() as u64;
        let last = self.last.load(Ordering::Relaxed);
        if elapsed >= last + self.period_nanos {
            self.update(0)
        }
    }

}

pub enum TelemetryItem {
    Metric(Arc<Metric>),
    MetricBuilder(Arc<MetricBuilder>)
}
    
pub struct TelemetryPrinter {
    last: AtomicU64,
    metrics_dynamic: lockfree::queue::Queue<TelemetryItem>,
    metrics_static: Vec<TelemetryItem>,
    period_seconds: u64, 
    start: Instant
}

impl TelemetryPrinter {

    /// Constructor
    pub fn with_params(period_seconds: u64, metrics: Vec<TelemetryItem>) -> Self {
        Self {
            last: AtomicU64::new(0),
            metrics_dynamic: lockfree::queue::Queue::new(),
            metrics_static: metrics, 
            period_seconds,                           
            start: Instant::now()
        }
    }

    /// Add dynamic metric 
    pub fn add_metric(&self, metric: TelemetryItem) {
        self.metrics_dynamic.push(metric)
    }

    /// Print if needed
    pub fn try_print(&self) {
        let elapsed = self.start.elapsed().as_secs();
        if elapsed > self.last.load(Ordering::Relaxed) { 
            log::info!(target: TARGET_TELEMETRY, "{:^39} {:^37}", "Metric", "Cur/Avg/Max/Total");
            log::info!(target: TARGET_TELEMETRY, "{:-<77}", "");
            for metric in self.metrics_static.iter() {
                Self::print_metric(metric)
            }
            let mut printed = Vec::new();
            while let Some(metric) = self.metrics_dynamic.pop() {
                Self::print_metric(&metric);
                printed.push(metric);
            }
            self.metrics_dynamic.extend(printed);
            self.last.store(elapsed + self.period_seconds, Ordering::Relaxed);
        }
    }

    fn print_metric(metric: &TelemetryItem) {
        let metric = match metric {
            TelemetryItem::Metric(metric) => metric,
            TelemetryItem::MetricBuilder(builder) => {
                builder.refresh();
                builder.metric()
            }
        };
        if let Some(totally) = metric.totally() {
            log::info!(
                target: TARGET_TELEMETRY, 
                "{:<39} {:>7}/{:>7}/{:>10}/{:>10}",
                metric.name(),
                metric.current(),
                metric.average(),
                metric.maximum(),
                totally
            )
        } else {
            log::info!(
                target: TARGET_TELEMETRY, 
                "{:<39} {:>7}/{:>7}/{:>10}",
                metric.name(),
                metric.current(),
                metric.average(),
                metric.maximum()
            )
        }
    }

}
