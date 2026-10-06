//! Python bindings for the Vahta detector.
//!
//! This module exists for one purpose: to let the **existing** Python test
//! suite run against the Rust implementation. It is a development and CI
//! artefact and is never a dependency of the released wheel.
//!
//! Two deliberate choices keep the surface small and the semantics exact.
//!
//! `HitSet` is **not** reimplemented. Rust computes the findings and then
//! fills the Python dataclass from `key_amnesia.detect_py`, calling its own
//! `record_assignment`. Highest-wins merging, reason ordering and the
//! `_rebuild` bookkeeping therefore remain literally the Python code, so they
//! cannot drift.
//!
//! Anything this module does not define — the legacy `ASSIGN` pattern object,
//! `collect_strings` over arbitrary Python containers, the constants — is
//! served by `detect_py` through the dispatcher's fallback. The port is
//! incremental on purpose, and the dispatcher reports exactly which names came
//! from here.

use pyo3::prelude::*;
use pyo3::types::{PyList, PyString, PyTuple};

use vahta_detect::classify::Confidence;

fn tier_str(tier: Confidence) -> &'static str {
    tier.as_str()
}

#[pyfunction]
fn entropy(s: &str) -> f64 {
    vahta_detect::entropy(s)
}

#[pyfunction]
fn transition_rate(s: &str) -> f64 {
    vahta_detect::transition_rate(s)
}

#[pyfunction]
fn is_placeholder(value: &str) -> bool {
    vahta_detect::classify::is_placeholder(value)
}

#[pyfunction]
fn is_secret_name(name: &str) -> bool {
    vahta_detect::is_secret_name(name)
}

#[pyfunction]
fn assignment_is_secret(value: &str) -> bool {
    vahta_detect::classify::assignment_is_secret(value)
}

/// `(tier, reason | None)` — never the value.
#[pyfunction]
fn classify_value<'py>(py: Python<'py>, value: &str) -> PyResult<Bound<'py, PyTuple>> {
    let (tier, reason) = vahta_detect::classify_value(value);
    let reason_obj: Py<PyAny> = match reason {
        Some(r) => PyString::new(py, r).into_any().unbind(),
        None => py.None(),
    };
    PyTuple::new(
        py,
        [
            PyString::new(py, tier_str(tier)).into_any().unbind(),
            reason_obj,
        ],
    )
}

#[pyfunction]
fn find_prefix_kind(value: &str) -> Option<&'static str> {
    vahta_detect::find_prefix_kind(value)
}

#[pyfunction]
fn classify_bearer_capture(text: &str) -> &'static str {
    tier_str(vahta_detect::classify_bearer_capture(text))
}

#[pyfunction]
fn find_secret_kind(text: &str) -> Option<String> {
    vahta_detect::find_secret_kind(text)
}

#[pyfunction]
fn looks_like_json_container(s: &str) -> bool {
    vahta_detect::looks_like_json_container(s)
}

/// Python's `_iter_assignments` is a generator; a list is an acceptable
/// stand-in because every caller either iterates it once or materialises it.
#[pyfunction]
#[pyo3(name = "_iter_assignments")]
fn iter_assignments<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    let pairs = vahta_detect::iter_assignments(text);
    let items: Vec<Py<PyAny>> = pairs
        .into_iter()
        .map(|(name, value)| -> PyResult<Py<PyAny>> {
            Ok(PyTuple::new(py, [name, value])?.into_any().unbind())
        })
        .collect::<PyResult<_>>()?;
    PyList::new(py, items)
}

#[pyfunction]
#[pyo3(name = "_iter_flag_values")]
fn iter_flag_values<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    let pairs = vahta_detect::iter_flag_values(text);
    let items: Vec<Py<PyAny>> = pairs
        .into_iter()
        .map(|(name, value)| -> PyResult<Py<PyAny>> {
            Ok(PyTuple::new(py, [name, value])?.into_any().unbind())
        })
        .collect::<PyResult<_>>()?;
    PyList::new(py, items)
}

/// Detect in Rust, then fill the **Python** `HitSet` so its own merge and
/// rebuild logic runs. Never carries values.
#[pyfunction]
fn scan_text_hits<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyAny>> {
    let computed = vahta_detect::scan_text_hits(text);
    build_hitset(py, &computed)
}

/// Fill the **Python** `HitSet` from a computed one, so its own
/// `record_assignment` runs and the merge and rebuild logic stays Python's.
fn build_hitset<'py>(
    py: Python<'py>,
    computed: &vahta_detect::HitSet,
) -> PyResult<Bound<'py, PyAny>> {
    let detect_py = py.import("key_amnesia.detect_py")?;
    let hit_set_cls = detect_py.getattr("HitSet")?;
    let hits = hit_set_cls.call0()?;

    if let Some(prefix) = computed.prefix {
        hits.setattr("prefix", prefix)?;
    }
    if computed.bearer_likely {
        hits.setattr("bearer_likely", true)?;
    }
    if computed.bearer_possible {
        hits.setattr("bearer_possible", true)?;
    }
    for name in &computed.flag_names {
        hits.getattr("flag_names")?
            .call_method1("append", (name,))?;
    }

    // Order is preserved from the Rust side, and `record_assignment` applies
    // the same highest-wins rule the Python path uses.
    for (name, reasons) in computed
        .likely_names
        .iter()
        .zip(computed.likely_reasons_by_name.iter())
    {
        hits.call_method1("record_assignment", (name, "likely", reasons.clone()))?;
    }
    for (name, reasons) in computed
        .possible_names
        .iter()
        .zip(computed.possible_reasons_by_name.iter())
    {
        hits.call_method1("record_assignment", (name, "possible", reasons.clone()))?;
    }
    Ok(hits)
}

/// Scan many texts, fold them in Rust, and build **one** Python `HitSet`.
///
/// The batched entry point is why this exists: crossing the boundary once per
/// string made the compiled path slower than Python on transcript trees.
#[pyfunction]
fn scan_texts<'py>(py: Python<'py>, texts: Vec<String>) -> PyResult<Bound<'py, PyAny>> {
    let computed = vahta_detect::hits::scan_texts(&texts);
    build_hitset(py, &computed)
}

#[pymodule]
fn _detect_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(entropy, m)?)?;
    m.add_function(wrap_pyfunction!(transition_rate, m)?)?;
    m.add_function(wrap_pyfunction!(is_placeholder, m)?)?;
    m.add_function(wrap_pyfunction!(is_secret_name, m)?)?;
    m.add_function(wrap_pyfunction!(assignment_is_secret, m)?)?;
    m.add_function(wrap_pyfunction!(classify_value, m)?)?;
    m.add_function(wrap_pyfunction!(find_prefix_kind, m)?)?;
    m.add_function(wrap_pyfunction!(classify_bearer_capture, m)?)?;
    m.add_function(wrap_pyfunction!(find_secret_kind, m)?)?;
    m.add_function(wrap_pyfunction!(looks_like_json_container, m)?)?;
    m.add_function(wrap_pyfunction!(iter_assignments, m)?)?;
    m.add_function(wrap_pyfunction!(iter_flag_values, m)?)?;
    m.add_function(wrap_pyfunction!(scan_text_hits, m)?)?;
    m.add_function(wrap_pyfunction!(scan_texts, m)?)?;
    Ok(())
}
