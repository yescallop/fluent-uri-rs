pub(crate) use crate::{
    builder::{
        state::{NonRefStart, Start},
        Builder,
    },
    component::{Authority, IAuthority, Scheme},
    encoding::{encoder::*, EStr, Encoder},
    error::{ParseError, ResolveError},
    internal::{Criteria, Meta, Parse, RiRef, Value},
    normalizer, resolver,
};
pub(crate) use alloc::{borrow::ToOwned, string::String};
pub(crate) use borrow_or_share::{BorrowOrShare, Bos};
pub(crate) use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt, hash,
    str::{self, FromStr},
};

#[cfg(feature = "serde")]
pub(crate) use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

macro_rules! cond {
    (if true { $($then:tt)* } else { $($else:tt)* }) => { $($then)* };
    (if false { $($then:tt)* } else { $($else:tt)* }) => { $($else)* };
}

macro_rules! ri_maybe_ref {
    (
        Type = $Ty:ident,
        type_name = $ty:literal,
        variable_name = $var:literal,
        name = $name:literal,
        indefinite_article = $art:literal,
        description = $desc:literal,
        must_be_ascii = $must_be_ascii:literal,
        must_have_scheme = $must_have_scheme:tt,
        rfc = $rfc:literal,
        abnf_rule = ($abnf:literal, $abnf_link:literal),
        $(
            NonRefType = $NonRefTy:ident,
            non_ref_name = $nr_name:literal,
            non_ref_link = $nr_link:literal,
            abnf_rule_absolute = ($abnf_abs:literal, $abnf_abs_link:literal),
            has_scheme_equivalent = $has_scheme_equiv:ident,
        )?
        $(
            RefType = $RefTy:ident,
            ref_name = $ref_name:literal,
        )?
        as_method = $as:ident,
        into_method = $into:ident,
        AuthorityType = $Authority:ident,
        UserinfoEncoderType = $UserinfoE:ident,
        RegNameEncoderType = $RegNameE:ident,
        PathEncoderType = $PathE:ident,
        QueryEncoderType = $QueryE:ident,
        FragmentEncoderType = $FragmentE:ident,
    ) => {
        #[doc = $desc]
        ///
        /// See the [crate-level documentation](crate#terminology) for an explanation of the above term(s).
        ///
        /// # Variants
        ///
        #[doc = concat!("Two variants of `", $ty, "` are available: ")]
        #[doc = concat!("`", $ty, "<&str>` (borrowed) and `", $ty, "<String>` (owned).")]
        ///
        #[doc = concat!("`", $ty, "<&'a str>`")]
        /// outputs references with lifetime `'a` where possible
        /// (thanks to [`borrow-or-share`](borrow_or_share)):
        ///
        /// ```
        #[doc = concat!("use fluent_uri::", $ty, ";")]
        ///
        #[doc = concat!("// Keep a reference to the path after dropping the `", $ty, "`.")]
        #[doc = concat!("let path = ", $ty, "::parse(\"foo:bar\")?.path();")]
        /// assert_eq!(path, "bar");
        /// # Ok::<_, fluent_uri::error::ParseError>(())
        /// ```
        ///
        /// # Comparison
        ///
        #[doc = concat!("`", $ty, "`s")]
        /// are compared [lexicographically](Ord#lexicographical-comparison)
        /// by their byte values. Normalization is **not** performed prior to comparison.
        ///
        /// # Examples
        ///
        /// Parse and extract components from
        #[doc = concat!($art, " ", $name, ":")]
        ///
        /// ```
        /// use fluent_uri::{
        ///     component::{Host, Scheme},
        ///     encoding::EStr,
        #[doc = concat!("    ", $ty, ",")]
        /// };
        ///
        /// const SCHEME_FOO: &Scheme = Scheme::new_or_panic("foo");
        ///
        /// let s = "foo://user@example.com:8042/over/there?name=ferret#nose";
        #[doc = concat!("let ", $var, " = ", $ty, "::parse(s)?;")]
        ///
        #[doc = concat!("assert_eq!(", $var, ".scheme()",
            cond!(if $must_have_scheme { "" } else { ".unwrap()" }), ", SCHEME_FOO);")]
        ///
        #[doc = concat!("let auth = ", $var, ".authority().unwrap();")]
        /// assert_eq!(auth.as_str(), "user@example.com:8042");
        /// assert_eq!(auth.userinfo().unwrap(), "user");
        /// assert_eq!(auth.host(), "example.com");
        /// assert!(matches!(auth.host_parsed(), Host::RegName(name) if name == "example.com"));
        /// assert_eq!(auth.port().unwrap(), "8042");
        /// assert_eq!(auth.port_to_u16(), Ok(Some(8042)));
        ///
        #[doc = concat!("assert_eq!(", $var, ".path(), \"/over/there\");")]
        #[doc = concat!("assert_eq!(", $var, ".query().unwrap(), \"name=ferret\");")]
        #[doc = concat!("assert_eq!(", $var, ".fragment().unwrap(), \"nose\");")]
        /// # Ok::<_, fluent_uri::error::ParseError>(())
        /// ```
        ///
        /// Parse into and convert between
        #[doc = concat!("`", $ty, "<&str>` and `", $ty, "<String>`:")]
        ///
        /// ```
        #[doc = concat!("use fluent_uri::", $ty, ";")]
        ///
        /// let s = "http://example.com/";
        ///
        #[doc = concat!("// Parse into a `", $ty, "<&str>` from a string slice.")]
        #[doc = concat!("let ", $var, ": ", $ty, "<&str> = ", $ty, "::parse(s)?;")]
        ///
        #[doc = concat!("// Parse into a `", $ty, "<String>` from an owned string.")]
        #[doc = concat!("let ", $var, "_owned: ", $ty, "<String> = ", $ty, "::parse(s.to_owned()).map_err(|e| e.strip_input())?;")]
        ///
        #[doc = concat!("// Convert a `", $ty, "<&str>` to `", $ty, "<String>`.")]
        #[doc = concat!("let ", $var, "_owned: ", $ty, "<String> = ", $var, ".to_owned();")]
        ///
        #[doc = concat!("// Borrow a `", $ty, "<String>` as `", $ty, "<&str>`.")]
        #[doc = concat!("let ", $var, ": ", $ty, "<&str> = ", $var, "_owned.borrow();")]
        /// # Ok::<_, fluent_uri::error::ParseError>(())
        /// ```
        #[derive(Clone, Copy)]
        pub struct $Ty<T> {
            /// Value of the URI (reference).
            val: T,
            /// Metadata of the URI (reference).
            /// Should be identical to parser output with `val` as input.
            meta: Meta,
        }

        impl<T> RiRef for $Ty<T> {
            type Val = T;
            type UserinfoE = $UserinfoE;
            type RegNameE = $RegNameE;
            type PathE = $PathE;
            type QueryE = $QueryE;
            type FragmentE = $FragmentE;

            fn new(val: T, meta: Meta) -> Self {
                Self { val, meta }
            }

            fn criteria() -> Criteria {
                Criteria {
                    must_be_ascii: $must_be_ascii,
                    must_have_scheme: $must_have_scheme,
                }
            }
        }

        impl<T> $Ty<T> {
            #[doc = concat!("Parses ", $art, " ", $name, " from a string into ", $art, " `", $ty, "`.")]
            ///
            /// The return type is
            ///
            #[doc = concat!("- `Result<", $ty, "<&str>, ParseError>` for `I = &str`;")]
            #[doc = concat!("- `Result<", $ty, "<String>, ParseError<String>>` for `I = String`.")]
            ///
            /// # Errors
            ///
            /// Returns `Err` if the string does not match the
            #[doc = concat!("[`", $abnf, "`][abnf] ABNF rule from RFC ", $rfc, ".")]
            ///
            /// From a [`ParseError<String>`], you may recover or strip the input
            /// by calling [`into_input`] or [`strip_input`] on it.
            ///
            #[doc = concat!("[abnf]: ", $abnf_link)]
            /// [`into_input`]: ParseError::into_input
            /// [`strip_input`]: ParseError::strip_input
            pub fn parse<I>(input: I) -> Result<Self, I::Err>
            where
                I: Parse<Val = T>,
            {
                input.parse()
            }
        }

        impl $Ty<String> {
            #[doc = concat!("Creates a new builder for ", $name, ".")]
            #[inline]
            pub fn builder() -> Builder<Self, cond!(if $must_have_scheme { NonRefStart } else { Start })> {
                Builder::new()
            }

            #[doc = concat!("Borrows this `", $ty, "<String>` as `", $ty, "<&str>`.")]
            #[allow(clippy::should_implement_trait)]
            #[inline]
            #[must_use]
            pub fn borrow(&self) -> $Ty<&str> {
                $Ty {
                    val: &self.val,
                    meta: self.meta,
                }
            }

            #[doc = concat!("Consumes this `", $ty, "<String>` and yields the underlying [`String`].")]
            #[inline]
            #[must_use]
            pub fn into_string(self) -> String {
                self.val
            }
        }

        impl $Ty<&str> {
            #[doc = concat!("Creates a new `", $ty, "<String>` by cloning the contents of this `", $ty, "<&str>`.")]
            #[inline]
            #[must_use]
            pub fn to_owned(&self) -> $Ty<String> {
                $Ty {
                    val: self.val.to_owned(),
                    meta: self.meta,
                }
            }
        }

        impl<T: Bos<str>> $Ty<T> {
            fn as_ref_loose(&self) -> Ref<'_, '_> {
                self.as_ref()
            }
        }

        impl<'i, 'o, T: BorrowOrShare<'i, 'o, str>> $Ty<T> {
            #[doc = concat!("Returns the ", $name, " as a string slice.")]
            #[must_use]
            pub fn as_str(&'i self) -> &'o str {
                self.val.borrow_or_share()
            }

            $(
                #[doc = concat!("Returns the ", $name, " as a borrowed ", $nr_name)]
                /// if it contains a scheme.
                pub fn $as(&'i self) -> Option<$NonRefTy<&'o str>> {
                    self.has_scheme().then(|| RiRef::new(self.as_str(), self.meta))
                }

                #[doc = concat!("Consumes this `", $ty, "` and creates a new `", stringify!($NonRefTy), "`")]
                /// with the same value if it contains a scheme.
                ///
                /// # Errors
                ///
                /// Returns `Err` containing `self` if it contains no scheme.
                pub fn $into(self) -> Result<$NonRefTy<T>, Self> {
                    if self.has_scheme() {
                        Ok(RiRef::new(self.val, self.meta))
                    } else {
                        Err(self)
                    }
                }
            )?

            $(
                #[doc = concat!("Returns the ", $name, " as a borrowed ", $ref_name, ".")]
                pub fn $as(&'i self) -> $RefTy<&'o str> {
                    RiRef::new(self.as_str(), self.meta)
                }

                #[doc = concat!("Consumes this `", $ty, "` and creates a new `", stringify!($RefTy), "`")]
                /// with the same contents.
                pub fn $into(self) -> $RefTy<T> {
                    RiRef::new(self.val, self.meta)
                }
            )?

            fn as_ref(&'i self) -> Ref<'o, 'i> {
                Ref::new(self.as_str(), &self.meta)
            }

            cond!(if $must_have_scheme {
                /// Returns the [scheme] component.
                ///
                /// Note that the scheme component is *case-insensitive*.
                /// See the documentation of [`Scheme`] for more details on comparison.
                ///
                /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.1
                ///
                /// # Examples
                ///
                /// ```
                #[doc = concat!("use fluent_uri::{component::Scheme, ", $ty, "};")]
                ///
                /// const SCHEME_HTTP: &Scheme = Scheme::new_or_panic("http");
                ///
                #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"http://example.com/\")?;")]
                #[doc = concat!("assert_eq!(", $var, ".scheme(), SCHEME_HTTP);")]
                /// # Ok::<_, fluent_uri::error::ParseError>(())
                /// ```
                #[must_use]
                pub fn scheme(&'i self) -> &'o Scheme {
                    self.as_ref().scheme()
                }
            } else {
                /// Returns the optional [scheme] component.
                ///
                /// Note that the scheme component is *case-insensitive*.
                /// See the documentation of [`Scheme`] for more details on comparison.
                ///
                /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.1
                ///
                /// # Examples
                ///
                /// ```
                #[doc = concat!("use fluent_uri::{component::Scheme, ", $ty, "};")]
                ///
                /// const SCHEME_HTTP: &Scheme = Scheme::new_or_panic("http");
                ///
                #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"http://example.com/\")?;")]
                #[doc = concat!("assert_eq!(", $var, ".scheme(), Some(SCHEME_HTTP));")]
                ///
                #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"/path/to/file\")?;")]
                #[doc = concat!("assert_eq!(", $var, ".scheme(), None);")]
                /// # Ok::<_, fluent_uri::error::ParseError>(())
                /// ```
                #[must_use]
                pub fn scheme(&'i self) -> Option<&'o Scheme> {
                    self.as_ref().scheme_opt()
                }
            });

            /// Returns the optional [authority] component.
            ///
            /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::", $ty, ";")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"http://example.com/\")?;")]
            #[doc = concat!("assert!(", $var, ".authority().is_some());")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"mailto:user@example.com\")?;")]
            #[doc = concat!("assert!(", $var, ".authority().is_none());")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn authority(&'i self) -> Option<$Authority<'o>> {
                self.as_ref().authority().map(Authority::cast)
            }

            /// Returns the [path] component.
            ///
            /// The path component is always present, although it may be empty.
            ///
            /// The returned [`EStr`] slice has extension methods for the path component.
            ///
            /// [path]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::", $ty, ";")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"http://example.com/\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".path(), \"/\");")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"mailto:user@example.com\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".path(), \"user@example.com\");")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"http://example.com\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".path(), \"\");")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn path(&'i self) -> &'o EStr<$PathE> {
                self.as_ref().path().cast()
            }

            /// Returns the optional [query] component.
            ///
            /// [query]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.4
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::{encoding::EStr, ", $ty, "};")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"http://example.com/?lang=en\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".query(), Some(EStr::new_or_panic(\"lang=en\")));")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"ftp://192.0.2.1/\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".query(), None);")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn query(&'i self) -> Option<&'o EStr<$QueryE>> {
                self.as_ref().query().map(EStr::cast)
            }

            /// Returns the optional [fragment] component.
            ///
            /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.5
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::{encoding::EStr, ", $ty, "};")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"http://example.com/#usage\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".fragment(), Some(EStr::new_or_panic(\"usage\")));")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"ftp://192.0.2.1/\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".fragment(), None);")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn fragment(&'i self) -> Option<&'o EStr<$FragmentE>> {
                self.as_ref().fragment().map(EStr::cast)
            }

            $(
                #[doc = concat!("Resolves the ", $name, " against the given base ", $nr_name)]
                #[doc = concat!("and returns the target ", $nr_name, ".")]
                ///
                #[doc = concat!("The base ", $nr_name)]
                /// **must** contain no fragment, i.e., match the
                #[doc = concat!("[`", $abnf_abs, "`][abnf] ABNF rule from RFC ", $rfc, ".")]
                ///
                /// This method applies the reference resolution algorithm defined in
                /// [Section 5 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-5),
                /// except for the following deviations:
                ///
                /// - If `base` contains no authority and its path is [rootless], then
                ///   `self` **must** either contain a scheme, be empty, or start with `'#'`.
                /// - When the target contains no authority and its path would start
                ///   with `"//"`, the string `"/."` is prepended to the path. This closes a
                ///   loophole in the original algorithm that resolving `".//@@"` against
                ///   `"foo:/"` yields `"foo://@@"` which is not a valid URI.
                /// - Percent-encoded dot segments (e.g. `"%2E"` and `".%2e"`) are also removed.
                ///   This closes a loophole in the original algorithm that resolving `".."`
                ///   against `"foo:/bar/.%2E/"` yields `"foo:/bar/"`, while first normalizing
                ///   the base and then resolving `".."` against it yields `"foo:/"`.
                /// - A slash (`'/'`) is appended to the base when it ends with a double-dot
                ///   segment. This closes a loophole in the original algorithm that resolving
                ///   `"."` against `"foo:/bar/.."` yields `"foo:/bar/"`, while first normalizing
                ///   the base and then resolving `"."` against it yields `"foo:/"`.
                ///
                /// No normalization except the removal of dot segments will be performed.
                /// Use [`normalize`] if necessary.
                ///
                #[doc = concat!("[abnf]: ", $abnf_abs_link)]
                /// [rootless]: EStr::<Path>::is_rootless
                /// [`normalize`]: Self::normalize
                ///
                /// This method has the property that
                /// `self.resolve_against(base).map(|r| r.normalize()).ok()` equals
                /// `self.normalize().resolve_against(&base.normalize()).ok()`.
                ///
                /// # Errors
                ///
                /// Returns `Err` if any of the above two **must**s is violated.
                ///
                /// # Examples
                ///
                /// ```
                #[doc = concat!("use fluent_uri::{", stringify!($NonRefTy), ", ", $ty, "};")]
                ///
                #[doc = concat!("let base = ", stringify!($NonRefTy), "::parse(\"http://example.com/foo/bar\")?;")]
                ///
                #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"baz\")?;")]
                #[doc = concat!("assert_eq!(", $var, ".resolve_against(&base).unwrap(), \"http://example.com/foo/baz\");")]
                ///
                #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"../baz\")?;")]
                #[doc = concat!("assert_eq!(", $var, ".resolve_against(&base).unwrap(), \"http://example.com/baz\");")]
                ///
                #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"?baz\")?;")]
                #[doc = concat!("assert_eq!(", $var, ".resolve_against(&base).unwrap(), \"http://example.com/foo/bar?baz\");")]
                /// # Ok::<_, fluent_uri::error::ParseError>(())
                /// ```
                pub fn resolve_against<U: Bos<str>>(
                    &self,
                    base: &$NonRefTy<U>,
                ) -> Result<$NonRefTy<String>, ResolveError> {
                    resolver::resolve(base.as_ref(), self.as_ref_loose()).map(RiRef::new_pair)
                }
            )?

            #[doc = concat!("Normalizes the ", $name, ".")]
            ///
            /// This method applies the syntax-based normalization described in
            /// [Section 6.2.2 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.2),
            /// which is effectively equivalent to taking the following steps in order:
            ///
            /// - Decode any percent-encoded octet that corresponds to an unreserved character.
            /// - Uppercase the hexadecimal digits within all percent-encoded octets.
            /// - Lowercase the scheme and the host except the percent-encoded octets.
            /// - Turn any IPv6 literal address into its canonical form as per
            ///   [RFC 5952](https://datatracker.ietf.org/doc/html/rfc5952).
            /// - If the port is empty, remove its `':'` delimiter.
            /// - If `self` contains a scheme and an absolute path, apply the
            ///   [`remove_dot_segments`] algorithm to the path, taking account of
            ///   percent-encoded dot segments as described at [`UriRef::resolve_against`].
            /// - If `self` contains no authority and its path would start with
            ///   `"//"`, prepend `"/."` to the path.
            ///
            /// [`UriRef::resolve_against`]: crate::UriRef::resolve_against
            ///
            /// This method is idempotent: `self.normalize()` equals `self.normalize().normalize()`.
            ///
            /// [`remove_dot_segments`]: https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::", $ty, ";")]
            ///
            #[doc = concat!("let ", $var, " = ", $ty, "::parse(\"eXAMPLE://a/./b/../b/%63/%7bfoo%7d\")?;")]
            #[doc = concat!("assert_eq!(", $var, ".normalize(), \"example://a/b/c/%7Bfoo%7D\");")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn normalize(&self) -> $Ty<String> {
                RiRef::new_pair(normalizer::normalize(self.as_ref_loose()))
            }

            $(
                /// Checks whether the
                #[doc = concat!($name, " is ", $art, " [", $nr_name, "][non-ref],")]
                /// i.e., contains a scheme.
                ///
                /// This method is equivalent to [`has_scheme`].
                ///
                #[doc = concat!("[non-ref]: ", $nr_link)]
                /// [`has_scheme`]: Self::has_scheme
                ///
                /// # Examples
                ///
                /// ```
                #[doc = concat!("use fluent_uri::", $ty, ";")]
                ///
                #[doc = concat!("assert!(", $ty, "::parse(\"http://example.com/\")?.", stringify!($has_scheme_equiv), "());")]
                #[doc = concat!("assert!(!", $ty, "::parse(\"/path/to/file\")?.", stringify!($has_scheme_equiv), "());")]
                /// # Ok::<_, fluent_uri::error::ParseError>(())
                /// ```
                #[must_use]
                pub fn $has_scheme_equiv(&self) -> bool {
                    self.has_scheme()
                }

                /// Checks whether a scheme component is present.
                ///
                /// # Examples
                ///
                /// ```
                #[doc = concat!("use fluent_uri::", $ty, ";")]
                ///
                #[doc = concat!("assert!(", $ty, "::parse(\"http://example.com/\")?.has_scheme());")]
                #[doc = concat!("assert!(!", $ty, "::parse(\"/path/to/file\")?.has_scheme());")]
                /// # Ok::<_, fluent_uri::error::ParseError>(())
                /// ```
                #[must_use]
                pub fn has_scheme(&self) -> bool {
                    self.as_ref_loose().has_scheme()
                }
            )?

            /// Checks whether an authority component is present.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::", $ty, ";")]
            ///
            #[doc = concat!("assert!(", $ty, "::parse(\"http://example.com/\")?.has_authority());")]
            #[doc = concat!("assert!(!", $ty, "::parse(\"mailto:user@example.com\")?.has_authority());")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn has_authority(&self) -> bool {
                self.as_ref_loose().has_authority()
            }

            /// Checks whether a query component is present.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::", $ty, ";")]
            ///
            #[doc = concat!("assert!(", $ty, "::parse(\"http://example.com/?lang=en\")?.has_query());")]
            #[doc = concat!("assert!(!", $ty, "::parse(\"ftp://192.0.2.1/\")?.has_query());")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn has_query(&self) -> bool {
                self.as_ref_loose().has_query()
            }

            /// Checks whether a fragment component is present.
            ///
            /// # Examples
            ///
            /// ```
            #[doc = concat!("use fluent_uri::", $ty, ";")]
            ///
            #[doc = concat!("assert!(", $ty, "::parse(\"http://example.com/#usage\")?.has_fragment());")]
            #[doc = concat!("assert!(!", $ty, "::parse(\"ftp://192.0.2.1/\")?.has_fragment());")]
            /// # Ok::<_, fluent_uri::error::ParseError>(())
            /// ```
            #[must_use]
            pub fn has_fragment(&self) -> bool {
                self.as_ref_loose().has_fragment()
            }
        }

        impl<T: Value> Default for $Ty<T> {
            #[doc = concat!("Creates an empty ", $name, ".")]
            fn default() -> Self {
                Self {
                    val: T::default(),
                    meta: Meta::default(),
                }
            }
        }

        impl<T: Bos<str>, U: Bos<str>> PartialEq<$Ty<U>> for $Ty<T> {
            fn eq(&self, other: &$Ty<U>) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl<T: Bos<str>> PartialEq<str> for $Ty<T> {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }

        impl<T: Bos<str>> PartialEq<$Ty<T>> for str {
            fn eq(&self, other: &$Ty<T>) -> bool {
                self == other.as_str()
            }
        }

        impl<T: Bos<str>> PartialEq<&str> for $Ty<T> {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl<T: Bos<str>> PartialEq<$Ty<T>> for &str {
            fn eq(&self, other: &$Ty<T>) -> bool {
                *self == other.as_str()
            }
        }

        impl<T: Bos<str>> Eq for $Ty<T> {}

        impl<T: Bos<str>> hash::Hash for $Ty<T> {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                self.as_str().hash(state);
            }
        }

        impl<T: Bos<str>> PartialOrd for $Ty<T> {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl<T: Bos<str>> Ord for $Ty<T> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.as_str().cmp(other.as_str())
            }
        }

        impl<T: Bos<str>> AsRef<str> for $Ty<T> {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl<T: Bos<str>> Borrow<str> for $Ty<T> {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl From<$Ty<&str>> for $Ty<String> {
            #[inline]
            fn from(value: $Ty<&str>) -> Self {
                value.to_owned()
            }
        }

        impl FromStr for $Ty<String> {
            type Err = ParseError;

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $Ty::parse(s).map(|r| r.to_owned())
            }
        }

        impl<T: Bos<str>> fmt::Debug for $Ty<T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct($ty)
                    .field("scheme", &self.scheme())
                    .field("authority", &self.authority())
                    .field("path", &self.path())
                    .field("query", &self.query())
                    .field("fragment", &self.fragment())
                    .finish()
            }
        }

        impl<T: Bos<str>> fmt::Display for $Ty<T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self.as_str(), f)
            }
        }

        #[cfg(feature = "serde")]
        impl<T: Bos<str>> Serialize for $Ty<T> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> Deserialize<'de> for $Ty<&'de str> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = <&str>::deserialize(deserializer)?;
                $Ty::parse(s).map_err(de::Error::custom)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> Deserialize<'de> for $Ty<String> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                $Ty::parse(s).map_err(de::Error::custom)
            }
        }
    };
}

/// A Rust reference to a URI (reference).
pub struct Ref<'v, 'm> {
    val: &'v str,
    meta: &'m Meta,
}

impl<'v, 'm> Ref<'v, 'm> {
    pub fn new(val: &'v str, meta: &'m Meta) -> Self {
        Self { val, meta }
    }

    pub fn as_str(&self) -> &'v str {
        self.val
    }

    fn slice(&self, start: usize, end: usize) -> &'v str {
        &self.val[start..end]
    }

    fn eslice<E: Encoder>(&self, start: usize, end: usize) -> &'v EStr<E> {
        EStr::new_validated(self.slice(start, end))
    }

    pub fn scheme_opt(&self) -> Option<&'v Scheme> {
        let end = self.meta.scheme_end?.get();
        Some(Scheme::new_validated(self.slice(0, end)))
    }

    pub fn scheme(&self) -> &'v Scheme {
        let end = self.meta.scheme_end.map_or(0, |i| i.get());
        Scheme::new_validated(self.slice(0, end))
    }

    pub fn authority(&self) -> Option<IAuthority<'v>> {
        let mut meta = self.meta.auth_meta?;
        let start = match self.meta.scheme_end {
            Some(i) => i.get() + 3,
            None => 2,
        };
        let end = self.meta.path_bounds.0;

        meta.host_bounds.0 -= start;
        meta.host_bounds.1 -= start;

        Some(Authority::new(self.slice(start, end), meta))
    }

    pub fn path(&self) -> &'v EStr<IPath> {
        self.eslice(self.meta.path_bounds.0, self.meta.path_bounds.1)
    }

    pub fn query(&self) -> Option<&'v EStr<IQuery>> {
        let end = self.meta.query_end?.get();
        Some(self.eslice(self.meta.path_bounds.1 + 1, end))
    }

    fn fragment_start(&self) -> Option<usize> {
        let query_or_path_end = match self.meta.query_end {
            Some(i) => i.get(),
            None => self.meta.path_bounds.1,
        };
        (query_or_path_end != self.val.len()).then_some(query_or_path_end + 1)
    }

    pub fn fragment(&self) -> Option<&'v EStr<IFragment>> {
        self.fragment_start()
            .map(|i| self.eslice(i, self.val.len()))
    }

    #[inline]
    pub fn has_scheme(&self) -> bool {
        self.meta.scheme_end.is_some()
    }

    #[inline]
    pub fn has_authority(&self) -> bool {
        self.meta.auth_meta.is_some()
    }

    #[inline]
    pub fn has_query(&self) -> bool {
        self.meta.query_end.is_some()
    }

    pub fn has_fragment(&self) -> bool {
        self.fragment_start().is_some()
    }
}
