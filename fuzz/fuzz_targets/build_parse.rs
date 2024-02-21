#![no_main]
use fluent_uri::{
    component::{Host, Scheme},
    encoding::{encoder::*, EStr},
    Builder, Uri,
};
use libfuzzer_sys::{
    arbitrary::{self, *},
    fuzz_target,
};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, Copy)]
struct SchemeWrapper<'a>(&'a Scheme);

impl<'a> Arbitrary<'a> for SchemeWrapper<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Scheme::try_new(u.arbitrary()?)
            .map(SchemeWrapper)
            .ok_or(Error::IncorrectFormat)
    }
}

struct EStrWrapper<'a, E: Encoder>(&'a EStr<E>);

impl<'a, E: Encoder> fmt::Debug for EStrWrapper<'a, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}

impl<'a, E: Encoder> Clone for EStrWrapper<'a, E> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<'a, E: Encoder> Copy for EStrWrapper<'a, E> {}

impl<'a, E: Encoder> Arbitrary<'a> for EStrWrapper<'a, E> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        EStr::try_new(u.arbitrary()?)
            .map(EStrWrapper)
            .ok_or(Error::IncorrectFormat)
    }
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum HostWrapper<'a> {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    RegName(EStrWrapper<'a, RegName>),
}

impl<'a> From<HostWrapper<'a>> for Host<'a> {
    fn from(wrapper: HostWrapper<'a>) -> Self {
        match wrapper {
            HostWrapper::Ipv4(addr) => Host::Ipv4(addr),
            HostWrapper::Ipv6(addr) => Host::Ipv6(addr),
            HostWrapper::RegName(name) => Host::RegName(name.0),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Port<'a>(&'a str);

impl<'a> Arbitrary<'a> for Port<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let s: &str = u.arbitrary()?;
        if s.bytes().all(|x| x.is_ascii_digit()) {
            Ok(Port(s))
        } else {
            Err(Error::IncorrectFormat)
        }
    }
}

#[derive(Arbitrary, Clone, Copy, Debug)]
struct Authority<'a> {
    userinfo: Option<EStrWrapper<'a, Userinfo>>,
    host: HostWrapper<'a>,
    port: Option<Port<'a>>,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
struct UriComponents<'a> {
    scheme: Option<SchemeWrapper<'a>>,
    authority: Option<Authority<'a>>,
    path: EStrWrapper<'a, Path>,
    query: Option<EStrWrapper<'a, Query>>,
    fragment: Option<EStrWrapper<'a, Fragment>>,
}

fn first_segment_contains_colon(path: &str) -> bool {
    path.split_once('/')
        .map(|x| x.0)
        .unwrap_or(path)
        .contains(':')
}

fuzz_target!(|c: UriComponents<'_>| {
    if c.authority.is_some() {
        if !c.path.0.is_empty() && c.path.0.is_rootless() {
            return;
        }
    } else {
        if c.path.0.as_str().starts_with("//") {
            return;
        }
        if c.scheme.is_none() && first_segment_contains_colon(c.path.0.as_str()) {
            return;
        }
    }

    let u1 = Uri::builder()
        .optional(Builder::scheme, c.scheme.map(|s| s.0))
        .optional(
            Builder::authority,
            c.authority.map(|a| {
                move |b: Builder<_>| {
                    b.optional(Builder::userinfo, a.userinfo.map(|s| s.0))
                        .host(a.host.into())
                        .optional(Builder::port, a.port.map(|s| s.0))
                }
            }),
        )
        .path(c.path.0)
        .optional(Builder::query, c.query.map(|s| s.0))
        .optional(Builder::fragment, c.fragment.map(|s| s.0))
        .build();

    assert_eq!(
        u1.scheme().map(|s| s.as_str()),
        c.scheme.map(|s| s.0.as_str())
    );
    assert_eq!(u1.authority().is_some(), c.authority.is_some());

    if let Some(a1) = u1.authority() {
        let a2 = c.authority.unwrap();
        assert_eq!(a1.userinfo(), a2.userinfo.map(|s| s.0));
        assert_eq!(a1.host_parsed(), a2.host.into());
        assert_eq!(a1.port(), a2.port.map(|s| s.0));
    }

    assert_eq!(u1.path(), c.path.0);
    assert_eq!(u1.query(), c.query.map(|s| s.0));
    assert_eq!(u1.fragment(), c.fragment.map(|s| s.0));

    let u2 = Uri::parse(&u1).unwrap();

    assert_eq!(
        u1.scheme().map(|s| s.as_str()),
        u2.scheme().map(|s| s.as_str())
    );
    assert_eq!(u1.authority().is_some(), u2.authority().is_some());

    if let Some(a1) = u1.authority() {
        let a2 = u2.authority().unwrap();
        assert_eq!(a1.as_str(), a2.as_str());
        assert_eq!(a1.userinfo(), a2.userinfo());
        assert_eq!(a1.host(), a2.host());

        match (a1.host_parsed(), a2.host_parsed()) {
            (Host::RegName(name), Host::Ipv4(addr)) => {
                assert_eq!(addr, name.as_str().parse::<Ipv4Addr>().unwrap());
            }
            (h1, h2) => assert_eq!(h1, h2),
        }

        assert_eq!(a1.port(), a2.port());
    }

    assert_eq!(u1.path(), u2.path());
    assert_eq!(u1.query(), u2.query());
    assert_eq!(u1.fragment(), u2.fragment());
});
