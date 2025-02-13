(function() {
    var type_impls = Object.fromEntries([["zkgroup",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#impl-Clone-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.84.1/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.84.1/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","zkgroup::common::serialization::ReservedByte"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#impl-Debug-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.84.1/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.84.1/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.84.1/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","zkgroup::common::serialization::ReservedByte"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#impl-Default-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/1.84.1/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","zkgroup::common::serialization::ReservedByte"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#82-95\">Source</a><a href=\"#impl-Deserialize%3C'de%3E-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#83-94\">Source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;D&gt;(deserializer: D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","zkgroup::common::serialization::ReservedByte"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#impl-PartialEq-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.84.1/src/core/cmp.rs.html#261\">Source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq","zkgroup::common::serialization::ReservedByte"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#73-80\">Source</a><a href=\"#impl-Serialize-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#74-79\">Source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;S&gt;(&amp;self, serializer: S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","zkgroup::common::serialization::ReservedByte"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TryFrom%3Cu8%3E-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#64-71\">Source</a><a href=\"#impl-TryFrom%3Cu8%3E-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#65\">Source</a><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.84.1/core/convert/trait.TryFrom.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionMismatchError.html\" title=\"struct zkgroup::common::serialization::VersionMismatchError\">VersionMismatchError</a>&lt;C&gt;</h4></section></summary><div class='docblock'>The type returned in the event of a conversion error.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#66-70\">Source</a><a href=\"#method.try_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.1/core/convert/trait.TryFrom.html#tymethod.try_from\" class=\"fn\">try_from</a>(value: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.1/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, Self::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.84.1/core/convert/trait.TryFrom.html#associatedtype.Error\" title=\"type core::convert::TryFrom::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Performs the conversion.</div></details></div></details>","TryFrom<u8>","zkgroup::common::serialization::ReservedByte"],["<section id=\"impl-Copy-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#impl-Copy-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section>","Copy","zkgroup::common::serialization::ReservedByte"],["<section id=\"impl-Eq-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#impl-Eq-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section>","Eq","zkgroup::common::serialization::ReservedByte"],["<section id=\"impl-StructuralPartialEq-for-VersionByte%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zkgroup/common/serialization.rs.html#49\">Source</a><a href=\"#impl-StructuralPartialEq-for-VersionByte%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.1/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.1/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;</h3></section>","StructuralPartialEq","zkgroup::common::serialization::ReservedByte"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[17808]}