//! Python bindings for the Vahta scanner.
//!
//! Like `_detect_rs`, this exists so the **existing** Python test suite can run
//! against the Rust implementation. It is a development and CI artefact and is
//! never a dependency of the released wheel.
//!
//! Rust computes; Python objects are built on the Python side. Findings leave
//! this module as `key_amnesia.scan_py.Finding` dataclass instances, and
//! findings that arrive are read attribute by attribute. Nothing here carries a
//! secret value, because nothing in `vahta-scan` does.
//!
//! Anything this module does not define — `scan_deep`, the transcript path,
//! `Finding` itself, the constants, `_MAX_CONTENT_BYTES` — is served by
//! `scan_py` through the dispatcher's fallback. A test that monkeypatches such a
//! constant is a test of the Python module; the compiled code cannot see it.
//!
//! Choices a reviewer should check:
//!
//! * **Scope.** Rust has `Project` and `Deep`; Python's field is a free `str`
//!   whose only values are `"project"` and `"deep"`, and every consumer tests
//!   `== "project"` or `!= "project"`. An incoming string maps to `Project` if
//!   it is exactly `"project"` and to `Deep` otherwise, which is the
//!   `!= "project"` reading. A finding passed through unchanged by identity
//!   (`importable_findings`) keeps its original string regardless.
//! * **Paths.** `Finding.path` is a `str`, as in Python. `iter_project_files`
//!   yields `pathlib.Path`; roots are accepted as `str` or `Path`.
//! * **Identity.** `importable_findings` returns the caller's own objects.

use std::path::PathBuf;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyFrozenSet, PyList, PyString};

use vahta_scan::finding::{self, Finding, Scope};
use vahta_scan::{report, walk};

fn scope_from_str(s: &str) -> Scope {
    if s == "project" { Scope::Project } else { Scope::Deep }
}

/// Read a Python `Finding` (any object with the same attributes) into Rust.
fn to_rust(f: &Bound<'_, PyAny>) -> PyResult<Finding> {
    let scope: String = f.getattr("scope")?.extract()?;
    let mut out = Finding::new(
        f.getattr("path")?.str()?.extract::<String>()?,
        f.getattr("kind")?.extract::<String>()?,
        scope_from_str(&scope),
    );
    out.secret_names = f.getattr("secret_names")?.extract()?;
    out.secret_count = f.getattr("secret_count")?.extract()?;
    out.reason = f.getattr("reason")?.extract()?;
    out.importable = f.getattr("importable")?.is_truthy()?;
    out.hit_lines = f.getattr("hit_lines")?.extract()?;
    out.confidence = f.getattr("confidence")?.extract()?;
    out.reasons = f.getattr("reasons")?.extract()?;
    let counts = f.getattr("reason_counts")?;
    let counts = counts
        .cast::<PyDict>()
        .map_err(|_| PyValueError::new_err("Finding.reason_counts must be a dict"))?;
    for (k, v) in counts.iter() {
        out.reason_counts.push((k.extract()?, v.extract()?));
    }
    Ok(out)
}

fn all_to_rust(findings: &Bound<'_, PyAny>) -> PyResult<Vec<Finding>> {
    findings.try_iter()?.map(|f| to_rust(&f?)).collect()
}

/// Build a Python `scan_py.Finding` from a Rust one.
fn to_python<'py>(py: Python<'py>, f: &Finding) -> PyResult<Bound<'py, PyAny>> {
    let cls = py.import("key_amnesia.scan_py")?.getattr("Finding")?;
    let counts = PyDict::new(py);
    for (k, v) in &f.reason_counts {
        counts.set_item(k, v)?;
    }
    let kwargs = PyDict::new(py);
    kwargs.set_item("path", &f.path)?;
    kwargs.set_item("kind", &f.kind)?;
    kwargs.set_item("secret_names", &f.secret_names)?;
    kwargs.set_item("secret_count", f.secret_count)?;
    kwargs.set_item("reason", &f.reason)?;
    kwargs.set_item("importable", f.importable)?;
    kwargs.set_item("scope", f.scope.as_str())?;
    kwargs.set_item("hit_lines", &f.hit_lines)?;
    kwargs.set_item("confidence", &f.confidence)?;
    kwargs.set_item("reasons", &f.reasons)?;
    kwargs.set_item("reason_counts", counts)?;
    cls.call((), Some(&kwargs))
}

fn list_to_python<'py>(py: Python<'py>, findings: &[Finding]) -> PyResult<Bound<'py, PyList>> {
    let items = findings
        .iter()
        .map(|f| to_python(py, f))
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, items)
}

#[pyfunction]
#[pyo3(signature = (path, *, scope))]
fn _findings_for_path<'py>(
    py: Python<'py>,
    path: PathBuf,
    scope: &str,
) -> PyResult<Bound<'py, PyList>> {
    let found = vahta_scan::content::findings_for_path(&path, scope_from_str(scope));
    list_to_python(py, &found)
}

#[pyfunction]
#[pyo3(signature = (root, *, include_excluded=false))]
fn scan_project<'py>(
    py: Python<'py>,
    root: PathBuf,
    include_excluded: bool,
) -> PyResult<Bound<'py, PyList>> {
    let found = py.detach(|| walk::scan_project(&root, include_excluded));
    list_to_python(py, &found)
}

/// Python's is a generator; an iterator over the computed list stands in.
#[pyfunction]
#[pyo3(signature = (root, *, include_excluded=false))]
fn iter_project_files<'py>(
    py: Python<'py>,
    root: PathBuf,
    include_excluded: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let files = py.detach(|| walk::project_files(&root, include_excluded));
    let path_cls = py.import("pathlib")?.getattr("Path")?;
    let items = files
        .iter()
        .map(|p| path_cls.call1((p,)))
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, items)?.try_iter().map(|i| i.into_any())
}

#[pyfunction]
#[pyo3(signature = (name, *, include_excluded))]
fn _should_skip_dir(name: &str, include_excluded: bool) -> bool {
    walk::should_skip_dir(name, include_excluded)
}

#[pyfunction]
#[pyo3(signature = (findings, *, strict="high"))]
fn leak_count(findings: &Bound<'_, PyAny>, strict: &str) -> PyResult<usize> {
    Ok(finding::leak_count(&all_to_rust(findings)?, strict))
}

#[pyfunction]
fn certain_count(findings: &Bound<'_, PyAny>) -> PyResult<usize> {
    Ok(report::certain_count(&all_to_rust(findings)?))
}

#[pyfunction]
fn likely_count(findings: &Bound<'_, PyAny>) -> PyResult<usize> {
    Ok(report::likely_count(&all_to_rust(findings)?))
}

#[pyfunction]
fn possible_count(findings: &Bound<'_, PyAny>) -> PyResult<usize> {
    Ok(report::possible_count(&all_to_rust(findings)?))
}

#[pyfunction]
fn transcript_line_hit_count(findings: &Bound<'_, PyAny>) -> PyResult<usize> {
    Ok(report::transcript_line_hit_count(&all_to_rust(findings)?))
}

#[pyfunction]
fn gated_confidences<'py>(py: Python<'py>, strict: &str) -> PyResult<Bound<'py, PyFrozenSet>> {
    let names = finding::gated_confidences(strict)
        .into_iter()
        .map(|c| PyString::new(py, c.as_str()))
        .collect::<Vec<_>>();
    PyFrozenSet::new(py, names)
}

#[pyfunction]
#[pyo3(signature = (findings, *, strict="high"))]
fn headline(findings: &Bound<'_, PyAny>, strict: &str) -> PyResult<String> {
    Ok(report::headline(&all_to_rust(findings)?, strict))
}

#[pyfunction]
fn _reason_bucket_counts<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    for (k, v) in report::reason_bucket_counts(&all_to_rust(findings)?) {
        out.set_item(k, v)?;
    }
    Ok(out)
}

#[pyfunction]
fn format_count_summary(findings: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(report::format_count_summary(&all_to_rust(findings)?))
}

#[pyfunction]
fn format_gate_totals(findings: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(report::format_gate_totals(&all_to_rust(findings)?))
}

#[pyfunction]
#[pyo3(signature = (findings, *, project_root, strict="high"))]
fn format_human_report(
    findings: &Bound<'_, PyAny>,
    project_root: &Bound<'_, PyAny>,
    strict: &str,
) -> PyResult<String> {
    let root: String = project_root.str()?.extract()?;
    Ok(report::format_human_report(&all_to_rust(findings)?, &root, strict))
}

/// Returns the caller's **own** objects, as Python does, not copies.
#[pyfunction]
fn importable_findings<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyList>> {
    let originals: Vec<Bound<'py, PyAny>> =
        findings.try_iter()?.collect::<PyResult<_>>()?;
    let converted = originals
        .iter()
        .map(to_rust)
        .collect::<PyResult<Vec<_>>>()?;
    let keep: Vec<&Finding> = report::importable_findings(&converted);
    let picked = converted
        .iter()
        .zip(originals)
        .filter(|(c, _)| keep.iter().any(|k| std::ptr::eq(*k, *c)))
        .map(|(_, o)| o)
        .collect::<Vec<_>>();
    PyList::new(py, picked)
}

#[pyfunction]
#[pyo3(signature = (findings, *, project_root))]
fn format_import_next_line(
    findings: &Bound<'_, PyAny>,
    project_root: &Bound<'_, PyAny>,
) -> PyResult<Option<String>> {
    let root: String = project_root.str()?.extract()?;
    Ok(report::format_import_next_line(&all_to_rust(findings)?, &root))
}

/// Rust returns the text; parsing it gives the dict Python's would be.
#[pyfunction]
#[pyo3(signature = (findings, *, project_root, strict="high"))]
fn findings_to_json<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyAny>,
    project_root: &str,
    strict: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let text = report::findings_to_json(&all_to_rust(findings)?, project_root, strict);
    py.import("json")?.call_method1("loads", (text,))
}

#[pymodule]
fn _scan_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(_findings_for_path, m)?)?;
    m.add_function(wrap_pyfunction!(scan_project, m)?)?;
    m.add_function(wrap_pyfunction!(iter_project_files, m)?)?;
    m.add_function(wrap_pyfunction!(_should_skip_dir, m)?)?;
    m.add_function(wrap_pyfunction!(leak_count, m)?)?;
    m.add_function(wrap_pyfunction!(certain_count, m)?)?;
    m.add_function(wrap_pyfunction!(likely_count, m)?)?;
    m.add_function(wrap_pyfunction!(possible_count, m)?)?;
    m.add_function(wrap_pyfunction!(transcript_line_hit_count, m)?)?;
    m.add_function(wrap_pyfunction!(gated_confidences, m)?)?;
    m.add_function(wrap_pyfunction!(headline, m)?)?;
    m.add_function(wrap_pyfunction!(_reason_bucket_counts, m)?)?;
    m.add_function(wrap_pyfunction!(format_count_summary, m)?)?;
    m.add_function(wrap_pyfunction!(format_gate_totals, m)?)?;
    m.add_function(wrap_pyfunction!(format_human_report, m)?)?;
    m.add_function(wrap_pyfunction!(importable_findings, m)?)?;
    m.add_function(wrap_pyfunction!(format_import_next_line, m)?)?;
    m.add_function(wrap_pyfunction!(findings_to_json, m)?)?;
    let frozen = PyFrozenSet::new(m.py(), walk::DEFAULT_EXCLUDE_DIR_NAMES.iter().copied())?;
    m.add("DEFAULT_EXCLUDE_DIR_NAMES", frozen)?;
    Ok(())
}
