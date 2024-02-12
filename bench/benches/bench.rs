use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fluent_uri::*;
use iref::UriRef;
use iri_string::types::UriReferenceStr;
use uriparse::URIReference;
use url::Url;

criterion_group!(
    benches,
    bench_parse,
    bench_parse_url,
    bench_parse_uriparse,
    bench_parse_iref,
    bench_parse_iri_string,
    bench_parse_oxiri,
);
criterion_main!(benches);

const PARSE_CASE: &str = "https://user@example.com/search?q=%E6%B5%8B%E8%AF%95#fragment";

fn bench_parse(c: &mut Criterion) {
    c.bench_function("parse", |b| b.iter(|| Uri::parse(black_box(PARSE_CASE))));
}

fn bench_parse_url(c: &mut Criterion) {
    c.bench_function("parse_url", |b| {
        b.iter(|| Url::parse(black_box(PARSE_CASE)))
    });
}

fn bench_parse_iref(c: &mut Criterion) {
    c.bench_function("parse_iref", |b| {
        b.iter(|| UriRef::new(black_box(PARSE_CASE)))
    });
}

fn bench_parse_uriparse(c: &mut Criterion) {
    c.bench_function("parse_uriparse", |b| {
        b.iter(|| URIReference::try_from(black_box(PARSE_CASE)))
    });
}

fn bench_parse_iri_string(c: &mut Criterion) {
    c.bench_function("parse_iri_string", |b| {
        b.iter(|| <&UriReferenceStr>::try_from(black_box(PARSE_CASE)))
    });
}

fn bench_parse_oxiri(c: &mut Criterion) {
    c.bench_function("parse_oxiri", |b| {
        b.iter(|| oxiri::IriRef::parse(black_box(PARSE_CASE)))
    });
}
