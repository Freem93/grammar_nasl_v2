#TRUSTED 292d85baabdd3fe671fb9a17bc6b2dbf9477c82ef04f9df97e24ab0770547a614ab7d83373d2a079ef9a682c953f3c6248f4bf6c2587a5005294ebc4309768635a87de21d8c63a510ab287d6ee87c8e88a6716382fcb37d61876c5a12b19e904b28edb69fcd47cf79e94b2338a23da6988f0c0de68dd62ee2cc45c5f0a0979768f8b68aaa288783e4f6a94d5897a1b67e93600c330cb203f6fd11d5034313e5bf801b046d175f4ef4a38b08dd3c482558d8d9feaf94d6ab93270afa9a011fd28a862e22323847f97558a7db402450aaa3470db0848abcd561013a87461daccbaf34c23ce21de51b2646c23ae1ceecd3cb863ab6f28785d6571d3e3f72fdc0f30d97ba9512d43c40b9bee5ff1735d951f67a1184fefc11b60f32c0d52aa41c7ae75e2cee881c31365c7fa9871d88ee1a6565677689810c8556dbd1b525fc15e449ed9d246dd8152b7607b0512b879fbff5fe37d7909c234a40f2abfd0bf973529b712c2da0b2342331c593bb013c6bc904de815a4145aac7910ee80cabf04a3ecc1d9863cfe06f4f9ae1f2c00676934b9e0a9df6d1296ce26e1c862f34d94cc1157c3b8c8c5f6e8d96ce72f781915ab461c0c85e5fd0342cfbb9e1dd8fe83a48c525355d83df6bf0b57de030f8edfd9d3f2de25cd9b2c08a5a135a8f8280ed8668d86aaae98b070882591c727af93f808bb570f2aadb2b978c3886b4917cca55d
# Mapping of EC curve names to OpenSSL's internal numeric identifier ("NIDs").
# These numbers come from OpenSSL in crypto/objects/obj_mac.num
#
# For curve name comparisons between SECG, NIST, and ANSI, see these docs:
# (TLS) https://tools.ietf.org/html/rfc4492#appendix-A
# (SSH) https://tools.ietf.org/html/rfc5656#section-10.2

curve_nid = {};

curve_nid.nist = {};
curve_nid.nist.B163 = 723;
curve_nid.nist.B233 = 727;
curve_nid.nist.B283 = 730;
curve_nid.nist.B409 = 732;
curve_nid.nist.B571 = 734;
curve_nid.nist.K163 = 721;
curve_nid.nist.K233 = 726;
curve_nid.nist.K283 = 729;
curve_nid.nist.K409 = 731;
curve_nid.nist.K571 = 733;
curve_nid.nist.P192 = 409;
curve_nid.nist.P224 = 713;
curve_nid.nist.P256 = 415;
curve_nid.nist.P384 = 715;
curve_nid.nist.P521 = 716;

# From RFC 5480 section 2.1.1.1
# These are all NIST curves.
curve_nid.oid = {};
curve_nid.oid["1.2.840.10045.3.1.1"] = curve_nid.nist.P192;
curve_nid.oid["1.3.132.0.1"]  = curve_nid.nist.K163;
curve_nid.oid["1.3.132.0.15"] = curve_nid.nist.B163;
curve_nid.oid["1.3.132.0.33"] = curve_nid.nist.P224;
curve_nid.oid["1.3.132.0.26"] = curve_nid.nist.K233;
curve_nid.oid["1.3.132.0.27"] = curve_nid.nist.B233;
curve_nid.oid["1.2.840.10045.3.1.7"] = curve_nid.nist.P256;
curve_nid.oid["1.3.132.0.16"] = curve_nid.nist.K283;
curve_nid.oid["1.3.132.0.17"] = curve_nid.nist.B283;
curve_nid.oid["1.3.132.0.34"] = curve_nid.nist.P384;
curve_nid.oid["1.3.132.0.36"] = curve_nid.nist.K409;
curve_nid.oid["1.3.132.0.37"] = curve_nid.nist.B409;
curve_nid.oid["1.3.132.0.35"] = curve_nid.nist.P521;
curve_nid.oid["1.3.132.0.38"] = curve_nid.nist.K571;
curve_nid.oid["1.3.132.0.39"] = curve_nid.nist.B571;

# From:
#   http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
# "IANA TLS Parameters: Supported Groups Registry"
curve_nid.tls = {};
# '0' is unassigned
curve_nid.tls[1]  = curve_nid.nist.K163;
curve_nid.tls[2]  = 722;
curve_nid.tls[3]  = curve_nid.nist.B163;
curve_nid.tls[4]  = 724;
curve_nid.tls[5]  = 725;
curve_nid.tls[6]  = curve_nid.nist.K233;
curve_nid.tls[7]  = curve_nid.nist.B233;
curve_nid.tls[8]  = 728;
curve_nid.tls[9]  = curve_nid.nist.K283;
curve_nid.tls[10] = curve_nid.nist.B283;
curve_nid.tls[11] = curve_nid.nist.K409;
curve_nid.tls[12] = curve_nid.nist.B409;
curve_nid.tls[13] = curve_nid.nist.K571;
curve_nid.tls[14] = curve_nid.nist.B571;
curve_nid.tls[15] = 708;
curve_nid.tls[16] = 709;
curve_nid.tls[17] = 710;
curve_nid.tls[18] = 711;
curve_nid.tls[19] = curve_nid.nist.P192;
curve_nid.tls[20] = 712;
curve_nid.tls[21] = curve_nid.nist.P224;
curve_nid.tls[22] = 714;
curve_nid.tls[23] = curve_nid.nist.P256;
curve_nid.tls[24] = curve_nid.nist.P384;
curve_nid.tls[25] = curve_nid.nist.P521;

function ecc_functions_available()
{
  if (defined_func("ecc_scalar_multiply") && defined_func("ecc_curve_details") && defined_func("bn_mod_inverse"))
    return TRUE;
  else
    return FALSE;
}

# Shift a bignum right by <bits> bits.
# Used only in ECDSA (generating 'z') when signing/verifying
function bn_rshift(bn, bits)
{
  return bn_div(bn, bn_exp(bn_dec2raw(string(2)), bn_dec2raw(string(bits))));
}

# Returns TRUE on successful verification or FALSE on failure
function ecdsa_verify(msg, x, y, r, s, hash, curve_nid)
{
  var point, curve_info, z, bits_to_drop, w, u1, u2;

  # Can't verify signatures if we're missing the builtins!
  if (!ecc_functions_available())
    return FALSE;

  curve_info = ecc_curve_details(curve_nid:curve_nid);
  if (isnull(curve_info))
    return FALSE;

  # Check that a public key is valid
  point = ecc_scalar_multiply(
    y:y,
    x:x,
    curve_nid:curve_nid,
    scalar:curve_info.order
  );
  if (!point.input_is_on_curve)
    return FALSE; # Point not on curve
  if (!point.result_is_at_infinity)
    return FALSE; # Point on curve, but is a "weak point"

  # Check that r and s are valid
  if (bn_cmp(key1:r, key2:curve_info.order) != -1 || bn_cmp(key1:r, key2:bn_dec2raw("0")) != 1)
    return FALSE; # r is out of range

  # Exact same check on 's' as the previous one for 'r'
  if (bn_cmp(key1:s, key2:curve_info.order) != -1 || bn_cmp(key1:s, key2:bn_dec2raw("0")) != 1)
    return FALSE; # s is out of range

  z = hash(msg);
  # Truncate Z if we need to (when the hash is bigger than the curve)
  if ((bits_to_drop = (strlen(z) * 8) - curve_info.order_bits) > 0)
    z = bn_rshift(bn:z, bits:bits_to_drop);

  w = bn_mod_inverse(s, curve_info.order);
  if (isnull(w))
    return FALSE;

  u1 = bn_mod_mul(z, w, curve_info.order);
  u2 = bn_mod_mul(r, w, curve_info.order);

  point = ecc_scalar_multiply(
    y:y,
    x:x,
    curve_nid:curve_nid,
    scalar:u2,
    g_scalar:u1
  );
  if (r != bn_mod(point.x, curve_info.order))
    return FALSE;

  return TRUE;
}

# This follows the procedure in SECG's SEC1v2 section 3.2.1
# This is appropriate for generating an ECDHE private key and for
# generating the per-signature 'k' when signing with ECDSA.
function ecc_generate_secret_key(curve_nid)
{
  local_var i, bits_to_generate, bytes, key, curve_info;

  curve_info = ecc_curve_details(curve_nid:curve_nid);
  bits_to_generate = strlen(curve_info.order) * 8;

  # 2**16 attempts picked for:
  # * Roughly 0.5 seconds of attempts before terminating
  # * Will never fail in practice, probability-wise
  for (i = 0; i < 2**16; ++i)
  {
    # Randomly generate a sequence of bytes
    # Check if, when treated as a bignum, it falls in the allowed range
    # for a secret key for this particular curve.
    key = random(need:bits_to_generate);
    # Greater than 0 and less than the order.
    if (bn_cmp(key1:key, key2:curve_info.order) == -1 && bn_cmp(key1:key, key2:bn_dec2raw("0")) == 1)
      return key;
  }

  # Bail. We can't safely generate a key and we can't require
  # plugin writers to handle this correctly. Negligible probability
  # of this ever happening... ever.
  exit(1, "Failed to generate an ECC secret key in " + i + " attempts");
}

##
# This should be replaced with the "degree" field from the ecc_curve_details
# builtin.
##
function _internal_ecc_curve_field_element_size(curve_nid)
{
  local_var nid_to_field_element_size;
  nid_to_field_element_size = {
    "409": 192,
    "415": 256,
    "708": 160,
    "709": 160,
    "710": 160,
    "711": 192,
    "712": 224,
    "713": 224,
    "714": 256,
    "715": 384,
    "716": 528,
    "721": 168,
    "722": 168,
    "723": 168,
    "724": 200,
    "725": 200,
    "726": 240,
    "727": 240,
    "728": 240,
    "729": 288,
    "730": 288,
    "731": 416,
    "732": 416,
    "733": 576,
    "734": 576
  };

  return nid_to_field_element_size[string(curve_nid)];
}

# FE2OSP: converts a single coordinate (x, or y) to a byte string that is a
# consistent maximum length. This is used when encoding a public key into an
# 'uncompressed' ('type 4') encoding in SSL and SSH.
# This is also used in SSL to encode the X coordinate from the shared
# secret, before it's derived into MAC and encryption keys.
function ecc_fe2osp(curve_nid, element)
{
  local_var field_element_size;
  # Typically this would be provided by the curve_info.degree hash field
  field_element_size = _internal_ecc_curve_field_element_size(curve_nid:curve_nid) / 8;
  return crap(data:'\x00', length:field_element_size - strlen(element)) + element;
}
