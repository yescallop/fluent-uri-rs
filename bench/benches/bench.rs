use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fluent_uri::*;
use iref::UriRef;
use iri_string::{
    format::ToDedicatedString,
    types::{UriAbsoluteStr, UriReferenceStr, UriStr},
};
use url::Url;

criterion_group!(
    benches,
    bench_parse,
    bench_parse_iref,
    bench_parse_iri_string,
    bench_parse_oxiri,
    bench_parse_url,
    bench_normalize,
    bench_normalize_iri_string,
    bench_resolve,
    bench_resolve_iri_string,
);
criterion_main!(benches);

const PARSE_CASE: &str = "https://user@example.com/search?q=%E6%B5%8B%E8%AF%95#fragment";
const NORMALIZE_CASE: &str = "eXAMPLE://a/./b/../b/%63/%7bfoo%7d";
const RESOLVE_CASE_BASE: &str = "http://example.com/foo/bar";
const RESOLVE_CASE_REF: &str = "../baz";

fn bench_parse(c: &mut Criterion) {
    c.bench_function("parse", |b| b.iter(|| Uri::parse(black_box(PARSE_CASE))));
}

fn bench_parse_iref(c: &mut Criterion) {
    c.bench_function("parse_iref", |b| {
        b.iter(|| UriRef::new(black_box(PARSE_CASE)))
    });
}

fn bench_parse_iri_string(c: &mut Criterion) {
    c.bench_function("parse_iri_string", |b| {
        b.iter(|| UriReferenceStr::new(black_box(PARSE_CASE)))
    });
}

fn bench_parse_oxiri(c: &mut Criterion) {
    c.bench_function("parse_oxiri", |b| {
        b.iter(|| oxiri::IriRef::parse(black_box(PARSE_CASE)))
    });
}

fn bench_parse_url(c: &mut Criterion) {
    c.bench_function("parse_url", |b| {
        b.iter(|| Url::parse(black_box(PARSE_CASE)))
    });
}

fn bench_normalize(c: &mut Criterion) {
    let uri = Uri::parse(NORMALIZE_CASE).unwrap();
    c.bench_function("normalize", |b| b.iter(|| uri.normalize()));
}

fn bench_normalize_iri_string(c: &mut Criterion) {
    let uri = UriStr::new(NORMALIZE_CASE).unwrap();
    c.bench_function("normalize_iri_string", |b| {
        b.iter(|| uri.normalize().to_dedicated_string())
    });
}

fn bench_resolve(c: &mut Criterion) {
    let base = Uri::parse(RESOLVE_CASE_BASE).unwrap();
    let r = Uri::parse(RESOLVE_CASE_REF).unwrap();
    c.bench_function("resolve", |b| b.iter(|| r.resolve(&base)));
}

fn bench_resolve_iri_string(c: &mut Criterion) {
    let base = UriAbsoluteStr::new(RESOLVE_CASE_BASE).unwrap();
    let r = UriReferenceStr::new(RESOLVE_CASE_REF).unwrap();
    c.bench_function("resolve_iri_string", |b| {
        b.iter(|| r.resolve_against(base).to_dedicated_string())
    });
}
