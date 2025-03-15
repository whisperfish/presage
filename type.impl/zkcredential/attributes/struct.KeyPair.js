(function() {
    var type_impls = Object.fromEntries([["zkgroup",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-Clone-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for KeyPair&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.85.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; KeyPair&lt;D&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.85.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.85.0/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.85.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.85.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ConstantTimeEq-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-ConstantTimeEq-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html\" title=\"trait subtle::ConstantTimeEq\">ConstantTimeEq</a> for KeyPair&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.ct_eq\" class=\"method trait-impl\"><a href=\"#method.ct_eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#tymethod.ct_eq\" class=\"fn\">ct_eq</a>(&amp;self, other: &amp;KeyPair&lt;D&gt;) -&gt; <a class=\"struct\" href=\"https://docs.rs/subtle/2.6.0/subtle/struct.Choice.html\" title=\"struct subtle::Choice\">Choice</a></h4></section></summary><div class='docblock'>Determine if two items are equal. <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#tymethod.ct_eq\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ct_ne\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://docs.rs/subtle/2.6.0/src/subtle/lib.rs.html#284\">Source</a><a href=\"#method.ct_ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#method.ct_ne\" class=\"fn\">ct_ne</a>(&amp;self, other: &amp;Self) -&gt; <a class=\"struct\" href=\"https://docs.rs/subtle/2.6.0/subtle/struct.Choice.html\" title=\"struct subtle::Choice\">Choice</a></h4></section></summary><div class='docblock'>Determine if two items are NOT equal. <a href=\"https://docs.rs/subtle/2.6.0/subtle/trait.ConstantTimeEq.html#method.ct_ne\">Read more</a></div></details></div></details>","ConstantTimeEq","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-Deserialize%3C'de%3E-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, D&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for KeyPair&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.219/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(\n    __deserializer: __D,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.85.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;KeyPair&lt;D&gt;, &lt;__D as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.219/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; KeyPair&lt;D&gt;<div class=\"where\">where\n    D: Domain,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.derive_from\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">derive_from</a>(sho: &amp;mut dyn ShoApi) -&gt; KeyPair&lt;D&gt;</h4></section></summary><div class=\"docblock\"><p>Generates a new KeyPair from the hash state in <code>sho</code>.</p>\n<p>Passing the same <code>sho</code> state in will produce the same key pair every time.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.inverse_of\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">inverse_of</a>&lt;D2&gt;(other: &amp;KeyPair&lt;D2&gt;) -&gt; KeyPair&lt;D&gt;<div class=\"where\">where\n    D2: Domain,</div></h4></section></summary><div class=\"docblock\"><p>Creates a KeyPair that’s the inverse of <code>other</code>.</p>\n<p>That is, if <code>k_inv</code> is <code>KeyPair::inverse_of(k)</code>, then <code>attr.as_points() == k_inv.encrypt(k.encrypt(&amp;attr))</code>.</p>\n<p>Note that the domain of <code>Self</code> doesn’t have to be related to the domain of <code>other</code>. This can\nbe useful when the inverted key is used on derived values.</p>\n<p>Don’t use this to decrypt points; there are more efficient ways to do that. See\n[<code>Self::decrypt_to_second_point</code>].</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.encrypt\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">encrypt</a>(&amp;self, attr: &amp;&lt;D as Domain&gt;::Attribute) -&gt; Ciphertext&lt;D&gt;</h4></section></summary><div class=\"docblock\"><p>Encrypts <code>attr</code> according to Chase-Perrin-Zaverucha section 4.1.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.encrypt_arbitrary_attribute\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">encrypt_arbitrary_attribute</a>&lt;D2&gt;(\n    &amp;self,\n    attr: &amp;dyn Attribute,\n) -&gt; Ciphertext&lt;D2&gt;</h4></section></summary><div class=\"docblock\"><p>Encrypts <code>attr</code> according to Chase-Perrin-Zaverucha section 4.1, even if the attribute is\nnot normally associated with this key.</p>\n<p>Allows controlling the domain of the resulting ciphertext, to not get confused with the\nusual ciphertexts produced by [<code>Self::encrypt</code>].</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.decrypt_to_second_point\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">decrypt_to_second_point</a>(\n    &amp;self,\n    ciphertext: &amp;Ciphertext&lt;D&gt;,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.85.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;RistrettoPoint, VerificationFailure&gt;</h4></section></summary><div class=\"docblock\"><p>Returns the second point from the plaintext that produced <code>ciphertext</code></p>\n<p>The encryption form allows recovering M2 from the ciphertext as <code>M2 = E_A2 - a2 * E_A1</code>. For\ncertain attributes, this may be enough to recover the value, making this a reversible\nencryption system. However, it is <strong>critical</strong> to check that the decoded value produces the\nsame <code>E_A1</code> when re-encrypted:</p>\n<div class=\"example-wrap\"><pre class=\"language-ignored\"><code>a1 * HashToPoint(DecodeFromPoint(M2)) == E_A1</code></pre></div>\n<p>This addresses the fact that this method is otherwise “garbage in, garbage out”: it will\n“decrypt” <em>any</em> ciphertext passed to it regardless of whether or not that ciphertext came\nfrom a valid plaintext, encrypted using the same key.</p>\n<p>Produces an error if <code>E_A1</code> is the Ristretto basepoint, which would imply that <code>a1</code> is not\nactually encrypting anything.</p>\n<p>Defined in Chase-Perrin-Zaverucha section 3.1.</p>\n</div></details></div></details>",0,"zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialDefault-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-PartialDefault-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; PartialDefault for KeyPair&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.partial_default\" class=\"method trait-impl\"><a href=\"#method.partial_default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">partial_default</a>() -&gt; KeyPair&lt;D&gt;</h4></section></summary><div class='docblock'>Returns a value that can be safely dropped or assigned over.</div></details></div></details>","PartialDefault","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-PartialEq-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for KeyPair&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.85.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;KeyPair&lt;D&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.85.0/src/core/cmp.rs.html#261\">Source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.85.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.85.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-Serialize-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for KeyPair&lt;D&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(\n    &amp;self,\n    __serializer: __S,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.85.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;&lt;__S as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, &lt;__S as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<section id=\"impl-Copy-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-Copy-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for KeyPair&lt;D&gt;</h3></section>","Copy","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"],["<section id=\"impl-Eq-for-KeyPair%3CD%3E\" class=\"impl\"><a href=\"#impl-Eq-for-KeyPair%3CD%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.85.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for KeyPair&lt;D&gt;</h3></section>","Eq","zkgroup::crypto::profile_key_encryption::KeyPair","zkgroup::crypto::uid_encryption::KeyPair"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[16196]}