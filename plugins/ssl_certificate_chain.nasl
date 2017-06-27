#TRUSTED 7fee3b12a01336c903152d596032ce247db68d89d6f09108e263a81219bb2db9f9df425fc53b1e3dea7d8d0ce1ba59af3ec83e8b2de4bbb20997730e09c113caca9bc20e799e5a32af33782610478f1bdc23f11aa2357176ab24e567a1a40fd55f9d0825a74a07aad3f6bc21096382e7efd32dab5e5e200de05b2888115f4571cb6fd18a8af995ff2ccae0bcf8dd0569cb38c7218f27022b173e75cdced2832f571693e49867623cb5848105ad502fb58c4fe07bb5181cb595a2abe74e812c071c3457f883e50143fda412244473f23025eb643162feea712695100ad5867472a86daeb5d1097db4fe446535a185671408076f478c94e2333ecbb2978962c694c8c53f0b5d803cb997773dd86975da37efff1d52664cea0d412dc44f8076803c767439489d93c43e39b697b00ccd8425142169ef9ae35db653cfd2cf9bb76d774bb284ab3a5c142b233f84a00d7ff3ffc452ca65d61c41d845fcc4225b8d8129b3af7c7472e9104857aef44aeca68d53567ad7fd60eaa50f3dcfc01f518bf3c45fd24ad5e70a35c968b21a7543e7816abff7375234ce01dc8c60d2d92b5b78b942bee62eea877b66504f6d5a32b731ea617d20c5e2b199e4441a31f0e18478b78934866493a00d14930c449d567ade49281902601aeb52854c1849e7080597249315d1d6ccba7e12002e741f462666f5017c06c984621f3ebd235479d353a640
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57571);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/18");

  script_name(english:"SSL Certificate Chain Analysis");
  script_summary(english:"Checks the certificate chain.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin sets KB items for use by other plugins.");
 script_set_attribute(attribute:"description", value:
"This plugin examines the chain of X.509 certificates used by this
service.");
  script_set_attribute(attribute:"solution", value:
"Alter the offending certificate's extensions and have it signed again.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("ssl_cert_expiry.nasl", "ssl_ca_setup.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("acap_func.inc");
include("datetime.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");
include("xmpp_func.inc");
include("audit.inc");
include("rsync.inc");
include("http.inc");
include("ocsp.inc");
include("ecc.inc");

global_var broken, CAs, CAs_raw, chain, port, unsorted, valid;

######################################################################
# Certificate Extension : Basic Constraints / Key Usage
######################################################################
function check_cert_ext_basic_constraints(cert, idx)
{
  local_var bc, critical, ku;

  # Ignore certificates that aren't X.509v3, since these rules don't
  # apply to them.
  if (cert["version"] != 2)
    return TRUE;

  # Extract key usage extension.
  ku = cert_get_ext(id:EXTN_KEY_USAGE, cert:cert);

  # Extract basic constraints extension.
  bc = cert_get_ext(id:EXTN_BASIC_CONSTRAINTS, cert:cert);

  # Extract basic constraints extension's critical boolean.
  critical = cert_get_ext(id:EXTN_BASIC_CONSTRAINTS, cert:cert, field:"critical");

  # RFC 5280, Section 4.2.1.9 :
  #
  # If the basic constraints extension is not present in a version 3
  # certificate, or the extension is present but the cA boolean is
  # not asserted, then the certified public key MUST NOT be used to
  # verify certificate signatures.
  if (isnull(bc))
    return
      'The certificate is missing the basic constraints extension which is\n' +
      'required for all X.509v3 certificates that sign others.';

  if (!bc["ca"])
    return
      'The certificate does not have the CA bit asserted in the basic\n' +
      'constraints extension, which is required for all certificates that\n' +
      'sign others.';

  if (!isnull(bc["pathlen"]))
  {
    # Many certificates found in the wild are missing the key usage
    # extension despite, having a pathlen. All examples found had the
    # critical boolean in the basic constraints extension set as
    # false. We'll use that as a heuristic.
    if (critical)
    {
      # RFC 5280, Section 4.2.1.9 :
      #
      # CAs MUST NOT include the pathLenConstraint field unless the cA
      # boolean is asserted and the key usage extension asserts the
      # keyCertSign bit.
      if (isnull(ku))
        return
          'The certificate is missing the key usage extension which is required\n' +
          'for all certificates that have a pathlen value in the basic\n' +
          'constraints extension.';

      if ((ku & keyCertSign) == 0)
        return
          'The certificate contains the key usage extension, but does not have\n' +
          'the keyCertSign bit asserted, which is required for all certificates\n' +
          'that have a pathlen value in the basic constraints extension.';
    }

    # RFC 5280, Section 4.2.1.9 :
    #
    # Where it appears, the pathLenConstraint field MUST be greater
    # than or equal to zero.
    if (bc["pathlen"] < 0)
      return 'The certificate has an invalid pathlen : ' + bc["pathlen"] + '.';

    # Things that don't seem like they should be valid but are :
    #
    #   - A certificate with a pathlen of m signing a certificate
    #     with a pathlen of n where n >= m.
    #   - A certificate with a pathlen restriction signing a
    #     certificate that has no pathlen restriction.
    #   - A certificate with a pathlen of zero signing a certificate
    #     that has a basic constraints extension, so long as it is
    #     the last link in the chain.
    #
    # RFC 5280, Section 4.2.1.9 :
    #
    # [Pathlen] gives the maximum number of non-self-issued
    # intermediate certificates that may follow this certificate in
    # a valid certification path. (Note: The last certificate in the
    # certification path is not an intermediate certificate, and is
    # not included in this limit. Usually, the last certificate is
    # an end entity certificate, but it can be a CA certificate.) A
    # pathLenConstraint of zero indicates that no non-self-issued
    # intermediate CA certificates may follow in a valid
    # certification path.
    #
    # RFC 5280, Section 6.1.4 :
    #
    # If the certificate was not self-issued, verify that
    # max_path_length is greater than zero and decrement
    # max_path_length by 1.
    #
    # If pathLenConstraint is present in the certificate and is less
    # than max_path_length, set max_path_length to the value of
    # pathLenConstraint.
    if (idx > 1 && idx - 1 > bc["pathlen"])
      return
        'The certificate has a pathlen of ' + bc["pathlen"] + ', but has ' + (idx - 1) + ' intermediate CA\n' +
        'certificates below it in the certificate chain.';

    if (!isnull(ku))
    {
      # Section 4.2.1.3 states that the key usage extension is
      # required in all signing certs, while Section 6.1.4 contains an
      # algorithm that treats the extension as optional. We'll treat
      # the extension as optional unless there's a pathlen value in
      # the basic constraints extension.
      #
      # RFC 5280, Section 4.2.1.3 :
      #
      # Conforming CAs MUST include this extension in certificates
      # that contain public keys that are used to validate digital
      # signatures on other public key certificates or CRLs.
      #
      # The keyCertSign bit is asserted when the subject public key is
      # used for verifying signatures on public key certificates. If
      # the keyCertSign bit is asserted, then the cA bit in the basic
      # constraints extension (Section 4.2.1.9) MUST also be asserted.
      if ((ku & keyCertSign) == 0)
        return
          'The certificate contains the key usage extension, but does not have\n' +
          'the keyCertSign bit asserted, which is required for all certificates\n' +
          'that sign others.';
    }
  }

  return TRUE;
}

######################################################################
# Root CA - Check if top of chain is self-signed with CA extension
#
# Note: This function should always run after check_chain_ca(), so that
# check_chain_ca() has already had the chance to add a known or custom
# CA certificate to the top of the chain
######################################################################
function check_root_ca()
{
  local_var alg, attr, bc, cert;

  cert = chain[max_index(chain)-1];
  bc = cert_get_ext(id:EXTN_BASIC_CONSTRAINTS, cert:cert["tbsCertificate"]);
  if(bc["ca"])
  {
    set_kb_item(name:"SSL/Chain/Top/"+port+"/CA", value:TRUE);

    # If the certificate at the top of the chain is a CA certificate and
    # is self-signed, then it is the root CA certificate
    if(is_self_signed(cert))
    {
      # Format the attributes that the plugin that reports this issue will
      # need in its output, to prevent having to re-parse the
      # certificates.
      alg = oid_name[cert["signatureAlgorithm"]];
      if(isnull(alg)) alg = "Unknown";
      cert = cert["tbsCertificate"];

      attr =
        'Subject             : ' + format_dn(cert["subject"]) + '\n' +
        'Issuer              : ' + format_dn(cert["issuer"]) + '\n' +
        'Valid From          : ' + cert["validity"]["notBefore"] + '\n' +
        'Valid To            : ' + cert["validity"]["notAfter"] + '\n' +
        'Signature Algorithm : ' + alg + '\n';

      set_kb_item(name:"SSL/Chain/Top/"+port+"/Self-Signed", value:TRUE);
      set_kb_item(name:"SSL/Chain/Root/" + port, value:attr);
    }

    # If the certificate at the top of the chain is a CA certificate and
    # is not self-signed, then it is an intermediate CA certificate with
    # an unknown issuer
    else
      set_kb_item(name:"SSL/Chain/Top/"+port+"/Self-Signed", value:FALSE);
  }
  else
  {
    set_kb_item(name:"SSL/Chain/Top/"+port+"/CA", value:FALSE);

    # If the certificate at the top of the chain is not a CA and is
    # self-signed, it is a self-generated server certificate
    if(is_self_signed(cert))
      set_kb_item(name:"SSL/Chain/Top/"+port+"/Self-Signed", value:TRUE);

    # If the certificate at the top of the chain is not a CA and is not
    # self-signed, it is just a server certificate with an unknown issuer
    else
      set_kb_item(name:"SSL/Chain/Top/"+port+"/Self-Signed", value:FALSE);
  }
}

function check_chain_ext_basic_constraints()
{
  local_var attr, bit, bits, cert, ext, i, j, key, reason;

  key = "SSL/Chain/Extension/BasicConstraints";
  j = 0;

  # Verify that each certificate in the chain is issued properly by
  # another one. The top certificate is the only one that can be
  # self-signed, which has special rules in the RFC. As a result, we
  # skip it. The final certificate in the chain is also skipped since
  # the RFC isn't explicit about its handling, so we'll play it safe.
  for (i = max_index(chain) - 2; i >= 1; i--)
  {
    # Extract the certificate from the chain, which we know to be
    # ordered.
    cert = chain[i]["tbsCertificate"];

    # Skip known certificates.
    if (find_issuer_idx(CA:CAs, cert:cert) >= 0)
      continue;

    # Check that the certificate has extensions that follow the RFC.
    reason = check_cert_ext_basic_constraints(idx:i, cert:cert);
    if (reason == TRUE)
      continue;

    # Note that since this check won't necessarily cause errors in SSL
    # clients, we don't mark the chain as invalid.

    # Extract attributes we want to report on.
    attr =
      'Subject           : ' + format_dn(cert["subject"]) + '\n' +
      'Issuer            : ' + format_dn(cert["issuer"]) + '\n' +
      'Version           : ' + (cert["version"] + 1) + '\n';

    # Add basic constraints extension contents.
    ext = cert_get_ext(id:EXTN_BASIC_CONSTRAINTS, cert:cert);
    if (!isnull(ext))
    {
      attr += "Basic Constraints : ";

      attr += "Critical:";
      if (cert_get_ext(id:EXTN_BASIC_CONSTRAINTS, field:"critical", cert:cert))
        attr += "TRUE";
      else
        attr += "FALSE";

      attr += ", CA:";
      if (ext["ca"])
        attr += "TRUE";
      else
        attr += "FALSE";

      if (!isnull(ext["pathlen"]))
        attr += ", pathlen:" + ext["pathlen"];

      attr += '\n';
    }

    # Add key usage extension contents.
    ext = cert_get_ext(id:EXTN_KEY_USAGE, cert:cert);
    if (!isnull(ext))
    {
      attr += "Key Usage         : ";

      attr += "Critical:";
      if (cert_get_ext(id:EXTN_KEY_USAGE, field:"critical", cert:cert))
        attr += "TRUE";
      else
        attr += "FALSE";

      bits = make_list();
      foreach bit (keys(key_usage))
      {
        if ((ext & bit) != 0)
          bits = make_list(bits, key_usage[bit]);
      }

      if (max_index(bits) > 0)
        attr += ", " + join(bits, sep:", ");

      attr += '\n';
    }

    # Record this certificate's specific error.
    set_kb_item(name:key + "/" + port + "/Attributes/" + j, value:attr);
    set_kb_item(name:key + "/" + port + "/Reason/" + j, value:reason);

    j++;
  }

  if (j != 0)
    set_kb_item(name:key, value:port);
}

######################################################################
# Certificate Expiry Failures
######################################################################
function check_chain_expired()
{
  local_var attr, cert, key, offset, subj, time, type, types, when, now,
            date_checks, compare_date, future_warning_days, cert_expired;

  types = make_array(
    "After",  " ",
    "Before", "  "
  );

  foreach cert (chain)
  {
    cert = cert["tbsCertificate"];

    # Extract attributes we want to report on.
    when = cert["validity"];
    subj = format_dn(cert["subject"]);

    future_warning_days = get_kb_item('SSL/settings/future_warning_days'); # set by ssl_cert_expiry.nasl
    if (future_warning_days <= 0)
      future_warning_days = 60;

    # Allow this part of the plugin to be tested without having to fake the system clock
    now = get_kb_item("TEST_ssl_certificate_chain_stubbed_unixtime");
    if (isnull(now))
      now = unixtime();

    date_checks = make_array("SSL/Chain/Expiry/", now, # now, should be first in list
                             "SSL/Chain/Future_Expiry/", now + (60*60*24*future_warning_days));

    cert_expired = FALSE;
    foreach key (keys(date_checks))
    {
      compare_date = date_checks[key];
      foreach type (keys(types))
      {
        time = when["not" + type];

        # Skip certificates that are within their valid range.
        offset = date_cmp(time, base_date:compare_date);
        if (
          (type == "After" && offset <= 0) ||
          (type == "Before" && offset >= 0)
        ) continue;

        # Mark the chain as having an error.
        if(key == "SSL/Chain/Expiry/")
        {
          broken = TRUE;
          valid = FALSE;
          cert_expired = TRUE;
        }
        else if(key == "SSL/Chain/Future_Expiry/")
        {
          # don't double report future expiry if certificate is already expired... 
          if(cert_expired) continue;
        }
        
        # Format the attributes that the plugin that reports this issue
        # will need in its output, to prevent having to reparse the
        # certificates.
        attr =
          'Subject ' + types[type] + ' : ' + subj + '\n' +
          'Not ' + type + ' : ' + time + '\n';
        set_kb_item(name:key + type + "/" + port, value:attr);
      }
    }
  }
}

######################################################################
# Certificate Signature Failures
######################################################################
function check_chain_signed()
{
  local_var alg, attr, cert, e, hash, i, key, n, pki, seq, sig, state, x, y, curve_oid;
  local_var subj, unsigned_cert;
  local_var chain_len;
  local_var issuer;

  key = "SSL/Chain/Signature/";

  chain_len = max_index(chain);
  for (i = 0; i < chain_len; i++)
  {
    cert = chain[i];

    # Extract the signature information from the certificate.
    alg = cert["signatureAlgorithm"];
    sig = cert["signatureValue"];

    # Find the issuing certificate, since we need its public key
    # information to extract check the signed hash of the certificate.
    if (i < chain_len - 1)
    {
      # Certificates should always be issued by subsequent
      # certificates due to the sorting done by check_chain_used().
      issuer = chain[i + 1];
      if (!is_signed_by(cert, issuer))
      {
        err_print(format_dn(cert["tbsCertificate"]["subject"]) + " is not signed by the subsequent certificate in the chain.");
        continue;
      }
    }
    else
    {
      # If the last certificate isn't self-signed, check_chain_ca()
      # will have flagged it.
      if (!is_self_signed(cert))
        continue;

      issuer = cert;
    }

    # Extract the public key from the certificate.
    pki = issuer["tbsCertificate"]["subjectPublicKeyInfo"];
    if (isnull(pki) || isnull(pki[1]))
    {
      state = "Algorithm/Unknown";
    }
    else if ("RSA" >< oid_name[alg])
    {
      n = pki[1][0];
      e = pki[1][1];

      if (ord(sig[0]) == 0)
        sig = substr(sig, 1, strlen(sig) - 1);
      if (ord(n[0]) == 0)
        n = substr(n, 1, strlen(n) - 1);

      # Decrypt the hash using the issuer's public key.
      hash = rsa_public_decrypt(sig:sig, n:n, e:e);

      # Extract the signed portion of the certificate, in DER format.
      seq = der_parse_sequence(seq:cert["raw"], list:TRUE);
      unsigned_cert = seq[1];

      # Verify that the signed hash from the signature matches the hash
      # we calculate.
      if (oid_name[alg] == "SHA-256 With RSA Encryption")
      {
        if (!defined_func("SHA256"))
          state = "Algorithm/Unsupported";
        else
          state = (SHA256(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "SHA-384 With RSA Encryption")
      {
        if (!defined_func("SHA384"))
          state = "Algorithm/Unsupported";
        else
          state = (SHA384(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "SHA-512 With RSA Encryption")
      {
        if (!defined_func("SHA512"))
          state = "Algorithm/Unsupported";
        else
          state = (SHA512(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "SHA-224 With RSA Encryption")
      {
        if (!defined_func("SHA224"))
          state = "Algorithm/Unsupported";
        else
          state = (SHA224(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "SHA-1 With RSA Encryption")
      {
        state = (SHA1(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "MD5 With RSA Encryption")
      {
        state = (MD5(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "MD4 With RSA Encryption")
      {
        state = (MD4(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "MD2 With RSA Encryption")
      {
        state = (MD2(unsigned_cert) >< hash);
      }
      else if (oid_name[alg] == "RSA-PSS Signature Scheme")
        state = "Algorithm/Unsupported";
      else
      {
        state = "Algorithm/Unknown";
      }
    }
    else if ("ECDSA" >< oid_name[alg] && ecc_functions_available())
    {
      x = pki[1][0];
      y = pki[1][1];
      curve_oid = pki[2];

      # Signatures are an ASN.1 BIT STRING for historical reasons, even
      # though inside the BIT STRING is a DER-encoded SEQUENCE of two
      # INTEGERS (for ECDSA signatures).
      # The first byte is the number of unused/padding bits in the BIT STRING,
      # and will always be zero for ECDSA signatures.
      if (ord(sig[0]) == 0)
        sig = substr(sig, 1);

      sig = parse_ecdsa_signaturevalue(sv:sig);

      # Extract the signed portion of the certificate, in DER format.
      seq = der_parse_sequence(seq:cert["raw"], list:TRUE);
      unsigned_cert = substr(seq[1], 0, strlen(seq[1]) - 2);

      # Verify that the signature on the certificate matches the signature we compute
      if (isnull(curve_nid.oid[curve_oid]))
      {
        state = "Curve/Unrecognized";
      }
      else if (oid_name[alg] == "ECDSA With SHA-256")
      {
        state = ecdsa_verify(curve_nid:curve_nid.oid[curve_oid], msg:unsigned_cert, x:x, y:y, r:sig.r, s:sig.s, hash:@SHA256);
      }
      else if (oid_name[alg] == "ECDSA With SHA-384")
      {
        state = ecdsa_verify(curve_nid:curve_nid.oid[curve_oid], msg:unsigned_cert, x:x, y:y, r:sig.r, s:sig.s, hash:@SHA384);
      }
      else if (oid_name[alg] == "ECDSA With SHA-512")
      {
        state = ecdsa_verify(curve_nid:curve_nid.oid[curve_oid], msg:unsigned_cert, x:x, y:y, r:sig.r, s:sig.s, hash:@SHA512);
      }
      else if (oid_name[alg] == "ECDSA With SHA-1")
      {
        state = ecdsa_verify(curve_nid:curve_nid.oid[curve_oid], msg:unsigned_cert, x:x, y:y, r:sig.r, s:sig.s, hash:@SHA1);
      }
      else
      {
        state = "Algorithm/Unknown";
      }
    }
    else if (!isnull(oid_name[alg]))
    {
      state = "Algorithm/Unsupported";
    }
    else
    {
      state = "Algorithm/Unknown";
    }

    # If nothing was wrong with this certificate, move on to the next
    # one.
    if (state == TRUE)
      continue;

    # Mark the chain as having an error.
    broken = TRUE;
    valid = FALSE;

    # Extract attributes we want to report on.
    subj = format_dn(cert["tbsCertificate"]["subject"]);

    # Format the attributes that the plugin that reports this issue
    # will need in its output, to prevent having to re-parse the
    # certificates.
    if (state == "Algorithm/Unknown")
    {
      attr =
        'Subject         : ' + subj + '\n' +
        'Algorithm (OID) : ' + alg + '\n';
    }
    else if (state == "Algorithm/Unsupported")
    {
      attr =
        'Subject          : ' + subj + '\n' +
        'Algorithm (Name) : ' + oid_name[alg] + '\n';
    }
    # This may happen if Ed25519 and other certificates become popular
    else if (state == "Curve/Unrecognized")
    {
      attr =
        'Subject          : ' + subj + '\n' +
        'Algorithm (Name) : ' + oid_name[alg] + '\n' +
        'EC Curve (OID)   : ' + curve_oid + '\n';
    }
    else
    {
      state = "Bad";
      attr =
        'Subject : ' + subj + '\n' +
        'Hash    : ' + hexstr(hash) + '\n';
    }

    set_kb_item(name:key + state + "/" + port, value:attr);
  }
}

######################################################################
# Certificate With Weak RSA Keys
######################################################################
function check_weak_rsa_keys()
{
  local_var attr, cert, key, len, min, min_list, weak_min_keylens, issued_year,
            issued_month, issued_day, temp, time, when;

  # 1024-bit RSA keys are considered to be the minimum safe length
  # nowadays.
  # keys less than 2048 bits will be considered unsafe by Microsoft
  # in October 2013
  min_list = make_list(1024, 2048);

  key = "SSL/Chain/WeakRSA_Under_";
  weak_min_keylens = make_list();

  foreach cert (chain)
  {
    # Only check RSA keys
    if ("RSA" >!< oid_name[cert["tbsCertificate"]["subjectPublicKeyInfo"][0]])
      continue;

    # Calculate the length of the certificate's public key.
    len = der_bit_length(cert, "tbsCertificate", "subjectPublicKeyInfo", 1, 0);
    if (isnull(len))
      continue;

    # Format the attributes that the plugin that reports this issue
    # will need in its output, to prevent having to re-parse the
    # certificates.
    attr =
      'Subject        : ' + format_dn(cert["tbsCertificate"]["subject"]) + '\n' +
      'RSA Key Length : ' + len + ' bits\n';

    foreach min (min_list)
    {
      # Determine if the key is strong enough.
      if (len == 0 || len >= min)
        continue;

      # Exception:
      # A Root CA Certificate issued prior to 31 Dec. 2010 with an RSA key size less than 2048 bits
      # MAY still serve as a trust anchor for Subscriber Certificate
      if (min == 2048 && is_self_signed(cert["tbsCertificate"]))
      {
        when = cert["tbsCertificate"]["validity"];
        time = when["notBefore"];
        temp = split(time, sep:" ", keep:FALSE);

        issued_year = int(temp[3]);
        issued_month = month_num_by_name(temp[0], base:1);
        issued_day = int(temp[1]);

        if (
          (issued_year < 2010) ||
          (issued_year == 2010 && issued_month < 12) ||
          (issued_year == 2010 && issued_month == 12 && issued_day < 31)
        ) continue;
      }

      weak_min_keylens = make_list(weak_min_keylens, min);

      set_kb_item(name:key + min, value: port);
      set_kb_item(name:key + min + "/" + port, value: attr);
    }
  }
}

######################################################################
# Certificate With Weak Hash Algorithm
######################################################################
function check_weak_hashes()
{
  local_var alg, attr, cert, key, key_ca, known_ca, weak_alg, weak_algs,
            subject,tag, when, issued_time, expire_time, expire_temp,
            expire_year, expire_month, expire_day;

  weak_algs = make_list(
    "1.2.840.113549.1.1.2", # MD2 with RSA Encryption
    "1.2.840.113549.1.1.3", # MD4 with RSA Encryption
    "1.2.840.113549.1.1.4", # MD5 with RSA Encryption
    "1.2.840.113549.1.1.5", # SHA1 with RSA Encryption
    "1.2.840.10045.4.1"     # ECDSA with SHA1
  );

  key    = "SSL/Chain/WeakHash";
  key_ca = "SSL/Chain/KnownCA/WeakHash";
  tag    = "SSL/Chain/SHA-1:JAN-DEC-16";

  foreach cert (chain)
  {
    # Exception:
    # If we flag certificates that are CAs with this check, we are
    # definitely going to get complaints. To avoid this, only flag
    # certificates that are below other certificates in our CA
    # databases to be reported on by ssl_weak_hash.nasl as Medium
    # severity. Flag CAs separately to be reported on by
    # ssl_weak_hash_ca.nasl as informational.
    #
    # Note: We send the subject to find_issuer_idx() because we want
    # to know if the certificate IS a known CA certificate, not if
    # it is ISSUED BY a known CA.
    known_ca = FALSE;
    subject = cert["tbsCertificate"]["subject"];
    if (find_issuer_idx(CA:CAs, issuer:subject, ignore_custom:TRUE) >= 0)
      known_ca = TRUE;

    # Get the hash algorithm used by the certificate.
    alg = cert["signatureAlgorithm"];
    if (isnull(alg))
      continue;

    foreach weak_alg (weak_algs)
    {
      # Algorithm is in the weak list *and* uses SHA-1.
      # RSA with SHA-1 or ECDSA with SHA-1.
      if (alg == weak_alg && ("1.2.840.113549.1.1.5" >< weak_alg || "1.2.840.10045.4.1" >< weak_alg))
      {
        when = cert["tbsCertificate"]["validity"];
        issued_time = when["notBefore"];
        expire_time = when["notAfter"];

        if (isnull(issued_time) || isnull(expire_time))
          exit(1, "The SSL certificate does not contain a valid date in the valid to or from fields.");

        expire_temp = split(expire_time, sep:" ", keep:FALSE);

        expire_year = int(expire_temp[3]);
        expire_month = month_num_by_name(expire_temp[0], base:1);
        expire_day = int(expire_temp[1]);

        # SHA-1 certificate that expires on or after January 1, 2017 should should be
        # reported in ssl_weak_hash.nasl
        if (int(expire_year) >= 2017 && int(expire_month) >= 01 && int(expire_day) >= 01)
        {
          # Format the attributes that the plugin that reports this issue
          # will need in its output, to prevent having to re-parse the
          # certificates.
          attr =
            'Subject             : ' + format_dn(cert["tbsCertificate"]["subject"]) + '\n' +
            'Signature Algorithm : ' + oid_name[alg] + '\n' +
            'Valid From          : ' + issued_time + '\n' +
            'Valid To            : ' + expire_time + '\n';
          if(known_ca)
          {
            set_kb_item(name:key_ca, value:port);
            set_kb_item(name:key_ca + "/" + port, value:attr);
          }
          else
          {
            set_kb_item(name:key, value:port);
            set_kb_item(name:key + "/" + port, value:attr);
          }
          break;
        }

        # SHA-1 certificate that expires between January 1, 2016 and December 31, 2016 should
        # be reported in an informational plugin.
        else if (int(expire_year) == 2016 && int(expire_month) <= 12 && int(expire_day) <= 31)
        {
          # Format the attributes that the plugin that reports this issue
          # will need in its output, to prevent having to re-parse the
          # certificates.
          attr =
            'Subject             : ' + format_dn(cert["tbsCertificate"]["subject"]) + '\n' +
            'Signature Algorithm : ' + oid_name[alg] + '\n' +
            'Valid From          : ' + issued_time + '\n' +
            'Valid To            : ' + expire_time + '\n';
          set_kb_item(name:tag, value:port);
          set_kb_item(name:tag + "/" + port, value:attr);
          break;
        }

        # SHA-1 certificate issued before January 1, 2016 should be discarded and ignored and
        # not reported in a plugin.
        else if (int(expire_year) < 2016)
        {
          break;
        }
      }

      else if (alg == weak_alg)
      {
        when = cert["tbsCertificate"]["validity"];
        issued_time = when["notBefore"];
        expire_time = when["notAfter"];

        if (isnull(issued_time) || isnull(expire_time))
          exit(1, "The SSL certificate does not contain dates in the valid to or from fields.");

        # Format the attributes that the plugin that reports this issue
        # will need in its output, to prevent having to re-parse the
        # certificates. Reporting for MD2, MD4, and MD5
        attr =
          'Subject             : ' + format_dn(cert["tbsCertificate"]["subject"]) + '\n' +
          'Signature Algorithm : ' + oid_name[alg] + '\n' +
          'Valid From          : ' + issued_time + '\n' +
          'Valid To            : ' + expire_time + '\n';
        if(known_ca)
        {
          set_kb_item(name:key_ca, value:port);
          set_kb_item(name:key_ca + "/" + port, value:attr);
        }
        else
        {
          set_kb_item(name:key, value:port);
          set_kb_item(name:key + "/" + port, value:attr);
        }
        break;
      }
    }
  }
}

######################################################################
# Certificate with a Certificate Revocation List URL
######################################################################
function check_crls()
{
  local_var cert, crl, ext, host, i, kb;

  crl = FALSE;
  host = get_host_name();
  kb = "SSL/CRL/" + get_host_name();

  for (i = 0; i < max_index(chain); i++)
  {
    cert = chain[i]["tbsCertificate"];

    # Don't check on the CRLs of CAs, since that'll generate even more
    # traffic.
    if (find_issuer_idx(CA:CAs, issuer:cert["subject"]) >= 0)
      continue;

    # Extract key CRL extension.
    ext = cert_get_ext(id:EXTN_CRL_DIST_POINTS, cert:cert);
    if (
      isnull(ext) ||
      isnull(ext[0]) ||
      isnull(ext[0]["distributionPoint"]) ||
      isnull(ext[0]["distributionPoint"][0]) ||
      isnull(ext[0]["distributionPoint"][0]["uniformResourceIdentifier"])
    ) continue;

    # Store CRL information in the global KB.
    kb = "SSL/CRL/" + host + "/" + port;
    set_global_kb_item(name:kb, value:i);
    kb += "/" + i;

    set_global_kb_item(
      name  : kb + "/URL",
      value : ext[0]["distributionPoint"][0]["uniformResourceIdentifier"]
    );
    set_global_kb_item(
      name  : kb + "/Subject",
      value : format_dn(cert["subject"])
    );

    crl = TRUE;
  }

  if (crl)
  {
    set_global_kb_item(name:"SSL/CRL/Host", value:host);
    set_global_kb_item(name:"SSL/CRL/" + host, value:port);
  }
}

######################################################################
# Validate the certificate(s) via OCSP
######################################################################
function check_ocsp()
{
  local_var key, i, ocsp_result, attr;

  if (!get_global_kb_item("global_settings/enable_crl_checking"))
  {
    return NULL;
  }

  key = "SSL/Chain/OCSP/";
  for (i = 0; i < max_index(chain); i++)
  {
    if (has_ocsp(server_der_cert:chain[i]["raw"]))
    {
      ocsp_result = do_ocsp(server_der_cert:chain[i]["raw"]);

      if (!isnull(ocsp_result['ocsp_failure']))
      {
        # This error is generally OCSP responder didn't reply or couldn't download
        # the issuer cert. It could be that the server is down/unreachable for a
        # moment, but I think its better to flag the whole thing as shady.
        broken = true;
        attr =
          'Subject             : ' + format_dn(chain[i]["tbsCertificate"]["subject"]) + '\n' +
          'OCSP Status         : ' + ocsp_result['ocsp_failure'] + '\n';
        set_kb_item(name:"SSL/Chain/OCSP/Status/" + port, value:attr);
      }
      else
      {
        if (isnull(ocsp_result['revocation_status']))
        {
          # This means we entirely failed parsing somehow. Originally I had this
          # flagging the certificate. However, I don't want to create false positives
          # so I'll just leave this stubbed out.
        }
        else if (ocsp_result['revocation_status'] == "Revoked")
        {
          broken = true;
          attr =
            'Subject             : ' + format_dn(chain[i]["tbsCertificate"]["subject"]) + '\n' +
            'OCSP Status         : Revoked\n';
          set_kb_item(name:"SSL/Chain/OCSP/Status/" + port, value:attr);
        }

        if (ocsp_result['verify_ocsp_response'] != "Valid Signature" &&
            "Unhandled Signature Algorithm" >!< ocsp_result['verify_ocsp_response'])
        {
          # This could be a general failure to decrypt the signature or just a bad signature
          broken = true;
          attr =
            'Subject             : ' + format_dn(chain[i]["tbsCertificate"]["subject"]) + '\n' +
            'OCSP Signature      : ' + ocsp_result['verify_ocsp_response'] + '\n';
          set_kb_item(name:"SSL/Chain/OCSP/Signature/" + port, value:attr);
        }
      }
    }
  }
}

######################################################################
# Certificate Authority Failures
######################################################################
function check_chain_ca()
{
  local_var attr, cert, copy, i, issuer, key, res;

  # Try and complete the certificate chain using the certificate
  # authorities that we know about.
  i = max_index(chain) - 1;
  while (TRUE)
  {
    cert = chain[i]["tbsCertificate"];

    # A valid chain ends on a self-signed certificate.
    if (is_self_signed(cert))
      break;

    # Try to find the certificate that signed the one at the top of
    # the chain.
    issuer = find_issuer_idx(CA:CAs, cert:cert);
    if (issuer < 0)
      break;

    # Keep the raw version of the certificate embedded, for verifying
    # signatures.
    copy = CAs[issuer];
    copy["raw"] = CAs_raw[issuer];

    # Add the signing certificate to the top of the chain.
    chain[++i] = copy;
  }

  # So long as the top certificate in the chain is signed by a known
  # CA, we're okay.
  if (find_issuer_idx(CA:CAs, cert:cert) >= 0)
    return 0;

  # Mark the chain as having an error.
  broken = TRUE;
  valid = FALSE;

  # Format the attributes that the plugin that reports this issue will
  # need in its output, to prevent having to re-parse the
  # certificates.
  attr =
    'Subject : ' + format_dn(cert["subject"]) + '\n' +
    'Issuer  : ' + format_dn(cert["issuer"]) + '\n';
  set_kb_item(name:"SSL/Chain/UnknownCA/" + port, value:attr);
}

######################################################################
# Self-Signed Certificates
######################################################################
function check_chain_self_signed()
{
  local_var attr, cert, key;

  # Get the certificate from the top of the chain.
  cert = chain[max_index(chain) - 1];
  cert = cert["tbsCertificate"];

  # Skip certificates that aren't self-signed.
  if (!is_self_signed(cert))
    return 0;

  # Known, self-signed certificates will return a non-negative index.
  # We're not interested in those, here.
  if (find_issuer_idx(CA:CAs, cert:cert) >= 0)
    return 0;

  # Mark the chain as having an error.
  # nb: it's not necessarily broken.
  valid = FALSE;

  # Save the unused certificates to the KB for use by other plugins.
  key = "SSL/Chain/SelfSigned";
  set_kb_item(name:key, value:port);
  key += "/" + port;

  # Format the attributes that the plugin that reports this issue will
  # need in its output, to prevent having to re-parse the
  # certificates.
  attr = 'Subject : ' + format_dn(cert["subject"]) + '\n';
  set_kb_item(name:key, value:attr);
}

######################################################################
# Unordered Certificates
######################################################################
function check_chain_sorted()
{
  local_var attr, cert, i, key, sorted;

  key = "SSL/Chain/Unordered";

  # If the sorted chain is the same as the unsorted chain, then it was
  # ordered and we're done.
  if (obj_cmp(chain, unsorted))
    return 0;

  # Mark the chain as having an error.
  # nb: it's not necessarily broken.
  valid = FALSE;

  # Save the fact that the chain was unordered to the KB for use by
  # other plugins.
  set_kb_item(name:key, value:port);

  # Format the attributes that the plugin that reports this issue will
  # need in its output, to prevent having to re-parse the
  # certificates.
  i = 0;
  key += "/" + port + "/";
  foreach cert (unsorted)
  {
    cert = cert["tbsCertificate"];
    attr =
      'Subject : ' + format_dn(cert["subject"]) + '\n' +
      'Issuer  : ' + format_dn(cert["issuer"]) + '\n';
    set_kb_item(name:key + i++, value:attr);
  }
}

######################################################################
# Unused Certificates
######################################################################
function check_chain_used()
{
  local_var attr, cert, key, res;

  # Sort the chain, returning both the used and unused certificates.
  res = sort_cert_chain(unsorted, filter:FALSE, raw:FALSE);
  if (isnull(res) || max_index(res[0]) == 0)
    exit(1, "Failed to sort certificate chain from port " + port + ".");

  # Store the ordered version of the chain, so the sort is only done
  # once.
  chain = res[0];

  # If there are no unused certificates, we're done.
  if (max_index(res[1]) == 0)
    return 0;

  # Mark the chain as having an error.
  # nb: it's not necessarily broken.
  valid = FALSE;

  # Save the unused certificates to the KB for use by other plugins.
  key = "SSL/Chain/Unused";
  set_kb_item(name:key, value:port);
  key += "/" + port;

  # Format the attributes that the plugin that reports this issue will
  # need in its output, to prevent having to re-parse the
  # certificates.
  foreach cert (res[1])
  {
    cert = cert["tbsCertificate"];
    attr = add_rdn_seq_nl(seq:cert["subject"]);
    set_kb_item(name:key, value:attr);
  }
}

######################################################################
# Main Body
######################################################################
get_kb_item_or_exit("SSL/Supported");

# Load up the certs of CAs we're aware of.
CAs = load_CA();
if (isnull(CAs) || isnull(CAs[0]) || max_index(CAs[0]) == 0)
  exit(1, "Could not load the list of SSL certificates.");
CAs_raw = CAs[1];
CAs = CAs[0];

# Get list of ports that use SSL or StartTLS.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Only consider open ports.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# Allow the plugin to be tested with just certificates in a KB with -k,
# instead of having to have an SSL server somewhere.
if (!get_kb_item("TEST_ssl_certificate_chain_do_not_open_socket"))
{
  # Open socket, sending StartTLS commands if necessary.
  soc = open_sock_ssl(port);
  if (!soc)
    exit(1, "Failed to connect to port " + port + ".");
}

# Retrieve the certificate chain the server is using for this port.
unsorted = get_server_cert(
  socket   : soc,
  port     : port,
  encoding : "der",
  getchain : TRUE,
  sort     : FALSE,
  securerenegotiation:TRUE
);
if (isnull(unsorted) || max_index(unsorted) == 0)
  exit(1, "Failed to retrieve the certificate chain from port " + port + ".");

# Parse the chain so that we only deal with parsed certificates in
# this plugin.
unsorted = parse_cert_chain(unsorted);
if (isnull(unsorted))
  exit(1, "Failed to parse certificate in chain on port " + port + ".");

# Run each check that we have on the certificate chain. The order of
# the checks is significant, since the chain starts unordered for the
# early checks, and is reordered for later checks.
broken = FALSE;
valid = TRUE;
check_chain_used();
check_chain_sorted();
check_chain_self_signed();
check_chain_ca();
check_crls();
check_ocsp();
check_weak_hashes();
check_weak_rsa_keys();
check_chain_signed();
check_chain_expired();
check_chain_ext_basic_constraints();
check_root_ca();

# Record whether the chain has any errors.
set_kb_item(name:"SSL/ValidCAChain/" + port, value:valid);
if (broken)
  set_kb_item(name:"SSL/BrokenCAChain", value:port);
