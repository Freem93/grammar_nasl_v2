#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82033);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2015-0207",
    "CVE-2015-0208",
    "CVE-2015-0209",
    "CVE-2015-0285",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0290",
    "CVE-2015-0291",
    "CVE-2015-0293",
    "CVE-2015-1787",
    "CVE-2016-0703",
    "CVE-2016-0704"
  );
  script_bugtraq_id(
    73225,
    73226,
    73227,
    73229,
    73230,
    73231,
    73232,
    73234,
    73235,
    73237,
    73238,
    73239
  );
  script_osvdb_id(
    118817,
    119328,
    119614,
    119673,
    119692,
    119755,
    119756,
    119757,
    119758,
    119759,
    119760,
    119761,
    135152,
    135153
  );

  script_name(english:"OpenSSL 1.0.2 < 1.0.2a Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server uses a version of
OpenSSL 1.0.2 prior to 1.0.2a. The OpenSSL library is, therefore,
affected by the following vulnerabilities :

  - A flaw exists in the DTLSv1_listen() function due to
    state being preserved in the SSL object from one
    invocation to the next. A remote attacker can exploit
    this, via crafted DTLS traffic, to cause a segmentation
    fault, resulting in a denial of service.
    (CVE-2015-0207)

  - A flaw exists in the rsa_item_verify() function due to
    improper implementation of ASN.1 signature verification.
    A remote attacker can exploit this, via an ASN.1
    signature using the RSA PSS algorithm and invalid
    parameters, to cause a NULL pointer dereference,
    resulting in a denial of service. (CVE-2015-0208)

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - A flaw exists in the ssl3_client_hello() function due to
    improper validation of a PRNG seed before proceeding
    with a handshake, resulting in insufficient entropy and
    predictable output. This allows a man-in-the-middle
    attacker to defeat cryptographic protection mechanisms
    via a brute-force attack, resulting in the disclosure of
    sensitive information. (CVE-2015-0285)

  - An invalid read flaw exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - A flaw exists with the 'multiblock' feature in the
    ssl3_write_bytes() function due to improper handling of
    certain non-blocking I/O cases. This allows a remote
    attacker to cause failed connections or a segmentation
    fault, resulting in a denial of service. (CVE-2015-0290)

  - A NULL pointer dereference flaw exists when handling
    clients attempting to renegotiate using an invalid
    signature algorithm extension. A remote attacker can
    exploit this to cause a denial of service.
    (CVE-2015-0291)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)

  - A flaw exists in the ssl3_get_client_key_exchange()
    function when client authentication and an ephemeral
    Diffie-Hellman ciphersuite are enabled. This allows a
    remote attacker, via a ClientKeyExchange message with a
    length of zero, to cause a denial of service.
    (CVE-2015-1787)

  - A key disclosure vulnerability exists in the SSLv2
    implementation in the get_client_master_key() function
    due to the acceptance of a nonzero CLIENT-MASTER-KEY
    CLEAR-KEY-LENGTH value for an arbitrary cipher. A
    man-in-the-middle attacker can exploit this to determine
    the MASTER-KEY value and decrypt TLS ciphertext data by
    leveraging a Bleichenbacher RSA padding oracle.
    (CVE-2016-0703)
   
  - An information disclosure vulnerability exists in the
    SSLv2 implementation in the get_client_master_key()
    function due to incorrectly overwriting MASTER-KEY bytes
    during use of export cipher suites. A remote attacker
    can exploit this to create a Bleichenbacher oracle.
    (CVE-2016-0704)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 1.0.2a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.2a', min:"1.0.2", severity:SECURITY_WARNING);
