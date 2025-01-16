(function() {
    var type_impls = Object.fromEntries([["zkgroup",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-Clone-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for PublicKey&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; PublicKey&lt;D&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.84.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.84.0/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.84.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ConstantTimeEq-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-ConstantTimeEq-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html\" title=\"trait subtle::ConstantTimeEq\">ConstantTimeEq</a> for PublicKey&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.ct_eq\" class=\"method trait-impl\"><a href=\"#method.ct_eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#tymethod.ct_eq\" class=\"fn\">ct_eq</a>(&amp;self, other: &amp;PublicKey&lt;D&gt;) -&gt; <a class=\"struct\" href=\"https://docs.rs/subtle/2.6.0/subtle/struct.Choice.html\" title=\"struct subtle::Choice\">Choice</a></h4></section></summary><div class='docblock'>Determine if two items are equal. <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#tymethod.ct_eq\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ct_ne\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://docs.rs/subtle/2.6.0/src/subtle/lib.rs.html#284\">Source</a><a href=\"#method.ct_ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#method.ct_ne\" class=\"fn\">ct_ne</a>(&amp;self, other: &amp;Self) -&gt; <a class=\"struct\" href=\"https://docs.rs/subtle/2.6.0/subtle/struct.Choice.html\" title=\"struct subtle::Choice\">Choice</a></h4></section></summary><div class='docblock'>Determine if two items are NOT equal. <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#method.ct_ne\">Read more</a></div></details></div></details>","ConstantTimeEq","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-Deserialize%3C'de%3E-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, D&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for PublicKey&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(\n    __deserializer: __D,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;PublicKey&lt;D&gt;, &lt;__D as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.217/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialDefault-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-PartialDefault-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; PartialDefault for PublicKey&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.partial_default\" class=\"method trait-impl\"><a href=\"#method.partial_default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">partial_default</a>() -&gt; PublicKey&lt;D&gt;</h4></section></summary><div class='docblock'>Returns a value that can be safely dropped or assigned over.</div></details></div></details>","PartialDefault","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-PartialEq-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for PublicKey&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;PublicKey&lt;D&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.84.0/src/core/cmp.rs.html#261\">Source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.84.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-Serialize-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for PublicKey&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(\n    &amp;self,\n    __serializer: __S,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.84.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;&lt;__S as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, &lt;__S as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.217/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"],["<section id=\"impl-Copy-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-Copy-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for PublicKey&lt;D&gt;</h3></section>","Copy","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"],["<section id=\"impl-Eq-for-PublicKey%3CD%3E\" class=\"impl\"><a href=\"#impl-Eq-for-PublicKey%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for PublicKey&lt;D&gt;</h3></section>","Eq","zkgroup::crypto::profile_key_encryption::PublicKey","zkgroup::crypto::uid_encryption::PublicKey"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[11910]}