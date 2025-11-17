use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use fluent_uri::{component::Scheme, pct_enc::EStr, Iri, Uri, UriRef};
use iri_string::{
    build::Builder,
    format::ToDedicatedString,
    types::{IriStr, UriAbsoluteStr, UriReferenceStr, UriStr},
};
use std::fs;
use std::hint::black_box;

criterion_group!(
    benches,
    bench_parse_uri,
    bench_parse_iri,
    bench_build,
    bench_normalize_uri,
    bench_normalize_iri,
    bench_normalize_iri_long,
    bench_resolve,
    bench_top100,
);
criterion_main!(benches);

const PARSE_URI_CASE: &str = "https://user@example.com/search?q=%E6%B5%8B%E8%AF%95#fragment";
const PARSE_IRI_CASE: &str = "https://用户@测试.com/search?q=我们测试解析IRI#fragment";
const NORMALIZE_URI_CASE: &str = "eXAMPLE://a/./b/../b/%63/%7bfoo%7d";
const NORMALIZE_IRI_CASE: &str = "https://%E7%94%A8%E6%88%B7@%E6%B5%8B%E8%AF%95.com/search?q=%E6%88%91%E4%BB%AC%E6%B5%8B%E8%AF%95%E8%A7%A3%E6%9E%90IRI#fragment";
const RESOLVE_CASE_BASE: &str = "http://example.com/foo/bar/baz/quz";
const RESOLVE_CASE_REF: &str = "../../../qux/./quux/../corge";

fn bench_parse_uri(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse-uri");
    group.bench_function("fluent-uri", |b| {
        b.iter(|| Uri::parse(black_box(PARSE_URI_CASE)))
    });
    group.bench_function("iref", |b| {
        b.iter(|| iref::Uri::new(black_box(PARSE_URI_CASE)))
    });
    group.bench_function("iri-string", |b| {
        b.iter(|| UriStr::new(black_box(PARSE_URI_CASE)))
    });
    group.finish();
}

fn bench_parse_iri(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse-iri");
    group.bench_function("fluent-uri", |b| {
        b.iter(|| Iri::parse(black_box(PARSE_IRI_CASE)))
    });
    group.bench_function("iref", |b| {
        b.iter(|| iref::Iri::new(black_box(PARSE_IRI_CASE)))
    });
    group.bench_function("iri-string", |b| {
        b.iter(|| IriStr::new(black_box(PARSE_IRI_CASE)))
    });
    group.bench_function("oxiri", |b| {
        b.iter(|| oxiri::Iri::parse(black_box(PARSE_IRI_CASE)))
    });
    group.finish();
}

fn bench_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("build");
    group.bench_function("fluent-uri", |b| {
        b.iter(|| {
            Uri::builder()
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
    group.bench_function("iri-string", |b| {
        b.iter(|| {
            let mut builder = Builder::new();
            builder.scheme("foo");
            builder.userinfo("user");
            builder.host("example.com");
            builder.port(8042u16);
            builder.path("/over/there");
            builder.query("name=ferret");
            builder.fragment("nose");
            builder.build::<UriStr>().unwrap().to_dedicated_string()
        })
    });
    group.finish();
}

fn bench_normalize_uri(c: &mut Criterion) {
    let r_fluent = Uri::parse(NORMALIZE_URI_CASE).unwrap();
    let r_iri = UriStr::new(NORMALIZE_URI_CASE).unwrap();

    let mut group = c.benchmark_group("normalize-uri");
    group.bench_function("fluent-uri", |b| b.iter(|| r_fluent.normalize()));
    group.bench_function("iri-string", |b| {
        b.iter(|| r_iri.normalize().to_dedicated_string())
    });
    group.finish();
}

fn bench_normalize_iri(c: &mut Criterion) {
    let r_fluent = Iri::parse(NORMALIZE_IRI_CASE).unwrap();
    let r_iri = IriStr::new(NORMALIZE_IRI_CASE).unwrap();

    let mut group = c.benchmark_group("normalize-iri");
    group.bench_function("fluent-uri", |b| b.iter(|| r_fluent.normalize()));
    group.bench_function("iri-string", |b| {
        b.iter(|| r_iri.normalize().to_dedicated_string())
    });
    group.finish();
}

fn bench_normalize_iri_long(c: &mut Criterion) {
    let case = format!("http://{}.com/", "%E6%B5%8B%E8%AF%95".repeat(50));

    let r_fluent = Iri::parse(&*case).unwrap();
    let r_iri = IriStr::new(&case).unwrap();

    let mut group = c.benchmark_group("normalize-iri-long");
    group.bench_function("fluent-uri", |b| b.iter(|| r_fluent.normalize()));
    group.bench_function("iri-string", |b| {
        b.iter(|| r_iri.normalize().to_dedicated_string())
    });
    group.finish();
}

fn bench_resolve(c: &mut Criterion) {
    let base_fluent = Uri::parse(RESOLVE_CASE_BASE).unwrap();
    let r_fluent = UriRef::parse(RESOLVE_CASE_REF).unwrap();

    let base_iri = UriAbsoluteStr::new(RESOLVE_CASE_BASE).unwrap();
    let r_iri = UriReferenceStr::new(RESOLVE_CASE_REF).unwrap();

    let mut group = c.benchmark_group("resolve");
    group.bench_function("fluent-uri", |b| {
        b.iter(|| r_fluent.resolve_against(&base_fluent))
    });
    group.bench_function("iri-string", |b| {
        b.iter(|| r_iri.resolve_against(base_iri).to_dedicated_string())
    });
    group.finish();
}

const TOP100_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/url-various-datasets/top100/top100.txt"
);

fn bench_top100(c: &mut Criterion) {
    let top100 = fs::read_to_string(TOP100_PATH).unwrap();
    let lines = top100.lines().collect::<Vec<&str>>();
    let total_bytes = lines.iter().map(|s| s.len() as u64).sum();

    let mut group = c.benchmark_group("parse-top100");
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("fluent-uri", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(Uri::parse(line));
            }
        })
    });
    group.bench_function("iri-string", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(UriStr::new(line));
            }
        })
    });
    group.bench_function("iref", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(iref::Uri::new(line));
            }
        })
    });
    group.finish();

    let mut group = c.benchmark_group("parse-iri-top100");
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("fluent-uri", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(Iri::parse(line));
            }
        })
    });
    group.bench_function("iri-string", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(IriStr::new(line));
            }
        })
    });
    group.bench_function("iref", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(iref::Iri::new(line));
            }
        })
    });
    group.bench_function("oxiri", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(oxiri::Iri::parse(line));
            }
        })
    });
    group.finish();

    let mut group = c.benchmark_group("parse-normalize-top100");
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("fluent-uri", |b| {
        b.iter(|| {
            for &line in &lines {
                if let Ok(uri) = Uri::parse(line) {
                    black_box(uri.normalize());
                }
            }
        })
    });
    group.bench_function("iri-string", |b| {
        b.iter(|| {
            for &line in &lines {
                if let Ok(uri) = UriStr::new(line) {
                    black_box(uri.normalize().to_dedicated_string());
                }
            }
        })
    });
    group.bench_function("url", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(url::Url::parse(line));
            }
        })
    });
    group.bench_function("ada-url", |b| {
        b.iter(|| {
            for &line in &lines {
                let _ = black_box(ada_url::Url::parse(line, None));
            }
        })
    });
    group.finish();

    let mut group = c.benchmark_group("parse-iri-normalize-top100");
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("fluent-uri", |b| {
        b.iter(|| {
            for &line in &lines {
                if let Ok(iri) = Iri::parse(line) {
                    black_box(iri.normalize());
                }
            }
        })
    });
    group.bench_function("iri-string", |b| {
        b.iter(|| {
            for &line in &lines {
                if let Ok(iri) = IriStr::new(line) {
                    black_box(iri.normalize().to_dedicated_string());
                }
            }
        })
    });
    group.finish();
}
