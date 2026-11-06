use std::fmt;

use serde_json::{Map, Value};
use tracing::{
    field::{Field, Visit},
    Event, Subscriber,
};
use tracing_subscriber::{
    fmt::{
        format::Writer,
        time::{FormatTime, SystemTime},
        FmtContext, FormatEvent, FormatFields,
    },
    registry::LookupSpan,
};

pub struct Json;

struct Fields(Map<String, Value>);

impl Fields {
    fn insert(&mut self, field: &Field, value: Value) {
        let name = if field.name() == "message" {
            "msg"
        } else {
            field.name()
        };
        self.0.insert(name.to_owned(), value);
    }
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, format!("{value:?}").into());
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, value.into());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, value.into());
    }
}

impl<S, N> FormatEvent<S, N> for Json
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut time = String::new();
        SystemTime.format_time(&mut Writer::new(&mut time))?;
        let mut fields = Fields(Map::new());
        fields.0.insert("time".into(), time.into());
        fields
            .0
            .insert("level".into(), event.metadata().level().as_str().into());
        event.record(&mut fields);
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&fields.0).map_err(|_| fmt::Error)?
        )
    }
}
