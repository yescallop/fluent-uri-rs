use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fluent_uri::{component::Scheme, encoding::EStr, Uri, UriRef};
use iri_string::{
    build::Builder,
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
    bench_build,
    bench_build_iri_string,
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
    c.bench_function("parse", |b| b.iter(|| UriRef::parse(black_box(PARSE_CASE))));
}

fn bench_parse_iref(c: &mut Criterion) {
    c.bench_function("parse_iref", |b| {
        b.iter(|| iref::UriRef::new(black_box(PARSE_CASE)))
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

fn bench_build(c: &mut Criterion) {
    c.bench_function("build", |b| {
        b.iter(|| {
            UriRef::builder()
                .scheme(Scheme::new_or_panic("foo"))
                .authority_with(|b| {
                    b.userinfo(EStr::new_or_panic("user"))
                        .host(EStr::new_or_panic("example.com"))
                        .port(8042)
                })
                .path(EStr::new_or_panic("/over/there"))
                .query(EStr::new_or_panic("name=ferret"))
                .fragment(EStr::new_or_panic("nose"))
                .build()
        })
    });
}

fn bench_build_iri_string(c: &mut Criterion) {
    c.bench_function("build_iri_string", |b| {
        b.iter(|| {
            let mut builder = Builder::new();
            builder.scheme("foo");
            builder.userinfo("user");
            builder.host("example.com");
            builder.port(8042u16);
            builder.path("/over/there");
            builder.query("name=ferret");
            builder.fragment("nose");
            builder
                .build::<UriReferenceStr>()
                .unwrap()
                .to_dedicated_string()
        })
    });
}

fn bench_normalize(c: &mut Criterion) {
    let r = UriRef::parse(NORMALIZE_CASE).unwrap();
    c.bench_function("normalize", |b| b.iter(|| r.normalize()));
}

fn bench_normalize_iri_string(c: &mut Criterion) {
    let r = UriStr::new(NORMALIZE_CASE).unwrap();
    c.bench_function("normalize_iri_string", |b| {
        b.iter(|| r.normalize().to_dedicated_string())
    });
}

fn bench_resolve(c: &mut Criterion) {
    let base = Uri::parse(RESOLVE_CASE_BASE).unwrap();
    let r = UriRef::parse(RESOLVE_CASE_REF).unwrap();
    c.bench_function("resolve", |b| b.iter(|| r.resolve_against(&base)));
}

fn bench_resolve_iri_string(c: &mut Criterion) {
    let base = UriAbsoluteStr::new(RESOLVE_CASE_BASE).unwrap();
    let r = UriReferenceStr::new(RESOLVE_CASE_REF).unwrap();
    c.bench_function("resolve_iri_string", |b| {
        b.iter(|| r.resolve_against(base).to_dedicated_string())
    });
}
