use std::{sync::{Arc, atomic::{AtomicU64, Ordering}}, time::Instant};

const TARGET_TELEMETRY: &str = "telemetry";

fn try_update(atomic: &AtomicU64, prev: u64, next: u64) -> bool {
    atomic.compare_exchange(prev, next, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

#[derive(Default)]
struct AveragePerSecond {
    count: AtomicU64,
    stamp: AtomicU64,
    value: AtomicU64
}

struct AveragePerPeriod {
    history: Vec<AveragePerSecond>,
    index: AtomicU64,
    start: Instant 
}

impl AveragePerPeriod {

    fn with_period(period_secs: u64) -> Self {
        let period_secs = if period_secs < 1 {
            2
        } else {
            period_secs + 1
        };
        let mut history = Vec::new();
        for _ in 0..period_secs {
            history.push(AveragePerSecond::default())
        }
        Self {
            history,
            index: AtomicU64::new(0),
            start: Instant::now()
        }
    }

    fn get_value(&self) -> u64 {
        let elapsed = self.start.elapsed().as_secs();
        let period = self.history.len() as u64;
        let mut count = 0;
        let mut value = 0;
        let mut index = self.index.load(Ordering::Relaxed) as usize;
        for offset in 0..period {
            let stamp = self.history[index].stamp.load(Ordering::Relaxed);
            // Exclude tail second if needed
            if elapsed - stamp >= period {
                break
            }
            if elapsed - stamp > offset {
                count += 1
            } else {
                // Exclude ongoing second
                if elapsed > stamp {
                    count += self.history[index].count.load(Ordering::Relaxed);
                    value += self.history[index].value.load(Ordering::Relaxed);
                }
                index = if index == 0 {
                    period as usize - 1
                } else {
                    index - 1
                }
            }
        }
        if count == 0 {
            0
        } else {
            value / count
        }
    }

    fn update(&self, update: u64) {
        loop {
            let elapsed = self.start.elapsed().as_secs();
            let index = self.index.load(Ordering::Relaxed) as usize;
            if elapsed > self.history[index].stamp.load(Ordering::Relaxed) {
                let next = if index + 1 >= self.history.len() {
                    0
                } else {
                    index + 1
                };
                if !try_update(&self.index, index as u64, next as u64) {
                    continue
                }
                self.history[next].count.store(1, Ordering::Relaxed);
                self.history[next].stamp.store(elapsed, Ordering::Relaxed);
                self.history[next].value.store(update, Ordering::Relaxed);
            } else {
                self.history[index].count.fetch_add(1, Ordering::Relaxed);    
                self.history[index].value.fetch_add(update, Ordering::Relaxed);    
            }
            break
        }            
    }

}

/// Simple metric
pub struct Metric {
    average: AveragePerPeriod,
    current: AtomicU64,
    maximum: AtomicU64,
    total_amount: Option<AtomicU64>,
    total_average: Option<(AtomicU64, AtomicU64)>,
    name: String
}

impl Metric {

    /// Construct without totals
    pub fn without_totals(name: &str, average_period_secs: u64) -> Arc<Self> {
        Self::construct(name, average_period_secs, false, false)
    }

    /// Construct with total amount
    pub fn with_total_amount(name: &str, average_period_secs: u64) -> Arc<Self> {
        Self::construct(name, average_period_secs, true, false)
    }

    /// Construct with total amount & average
    pub fn with_total_amount_and_average(name: &str, average_period_secs: u64) -> Arc<Self> {
        Self::construct(name, average_period_secs, true, true)
    }

    /// Construct with total average
    pub fn with_total_average(name: &str, average_period_secs: u64) -> Arc<Self> {
        Self::construct(name, average_period_secs, false, true)
    }

    /// Get average value per period
    pub fn get_average(&self) -> u64 {
        self.average.get_value()
    }

    /// Get current value
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::Relaxed)
    }

    /// Get maximum value
    pub fn maximum(&self) -> u64 {
        self.maximum.load(Ordering::Relaxed)
    }

    /// Get total amount value
    pub fn total_amount(&self) -> Option<u64> {
        self.total_amount.as_ref().map(|total| total.load(Ordering::Relaxed))
    }

    /// Get total average value
    pub fn total_average(&self) -> Option<u64> {
        self.total_average.as_ref().map(|(_, average)| average.load(Ordering::Relaxed))
    }

    /// Get metric name
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Update metric
    pub fn update(&self, update: u64) {
        // Calculate average per period
        self.average.update(update);
        // Calculate maximum
        loop {
            let maximum = self.maximum.load(Ordering::Relaxed);
            #[allow(clippy::collapsible_if)]
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
        // Calculate total average with Welford's method
        if let Some((counter, average)) = &self.total_average {
            loop {
                let counter_val = counter.load(Ordering::Relaxed);
                let average_val = average.load(Ordering::Relaxed);
                let update = ((update as i128 - average_val as i128) / 
                    (counter_val as i128 + 1)) as u64;
                if !try_update(counter, counter_val, counter_val + 1) {
                    continue
                }
                if !try_update(average, average_val, average_val + update) {
                    counter.fetch_sub(1, Ordering::Relaxed);
                    continue
                }
                break
            }
        }
        // Store total amount
        self.total_amount.as_ref().map(|amount| amount.fetch_add(update, Ordering::Relaxed));
    }

    fn construct(
        name: &str, 
        average_period_secs: u64,
        with_total_amount: bool,
        with_total_average: bool
    ) -> Arc<Self> {
        let ret = Self {
            average: AveragePerPeriod::with_period(average_period_secs),
            current: AtomicU64::new(0),
            maximum: AtomicU64::new(0),
            total_amount: if with_total_amount {
                Some(AtomicU64::new(0))
            } else {
                None
            },
            total_average: if with_total_average {
                Some((AtomicU64::new(0), AtomicU64::new(0)))
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
    value: AtomicU64
}

impl MetricBuilder {

    /// Constructor
    pub fn with_metric_and_period(metric: Arc<Metric>, period_nanos: u64) -> Arc<Self> {
        let ret = Self {
            last: AtomicU64::new(0),
            metric,
            period_nanos: if period_nanos < 1 {
                1
            } else {
                period_nanos
            },
            value: AtomicU64::new(0)
        };
        Arc::new(ret)
    }

    /// Get metric
    pub fn metric(&self) -> &Arc<Metric> {
        self.update(0);
        &self.metric
    }

    /// Update value 
    pub fn update(&self, update: u64) {
        loop {
            let elapsed = self.metric.average.start.elapsed().as_nanos();
            let elapsed = (elapsed / self.period_nanos as u128) as u64;
            let last = self.last.load(Ordering::Relaxed);
            if elapsed > last {
                if self.last.compare_exchange(
                    last, 
                    elapsed,
                    Ordering::Relaxed,
                    Ordering::Relaxed
                ).is_err() {
                    continue
                }
                for _ in last..elapsed - 1 {
                    self.metric.update(0);
                }
                self.metric.update(self.value.swap(update, Ordering::Relaxed));
            } else {
                self.value.fetch_add(update, Ordering::Relaxed);
            } 
            break          
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
            let mut out = format!(
                "\n{:^39} {:^37}\n{:-<77}\n", "Metric", "Cur/Avg/Max/Total", ""
            );
            for metric in self.metrics_static.iter() {
                Self::print_metric(&mut out, metric)
            }
            let mut printed = Vec::new();
            while let Some(metric) = self.metrics_dynamic.pop() {
                Self::print_metric(&mut out, &metric);
                printed.push(metric);
            }
            self.metrics_dynamic.extend(printed);
            self.last.store(elapsed + self.period_seconds, Ordering::Relaxed);
            log::info!(target: TARGET_TELEMETRY, "{}", out);
        }
    }

    fn print_metric(out: &mut String, metric: &TelemetryItem) {
        let metric = match metric {
            TelemetryItem::Metric(metric) => metric,
            TelemetryItem::MetricBuilder(builder) => builder.metric()
        };
        let update = if let Some(amount) = metric.total_amount() {
            format!(
                "{:<39} {:>7}/{:>7}/{:>10}/{:>10}\n",
                metric.name(),
                metric.current(),
                metric.get_average(),
                metric.maximum(),
                amount
            )
        } else {
            format!(
                "{:<39} {:>7}/{:>7}/{:>10}\n",
                metric.name(),
                metric.current(),
                metric.get_average(),
                metric.maximum()
            )
        };
        out.push_str(update.as_str());
    }

}
