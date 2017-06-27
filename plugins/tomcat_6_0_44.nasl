#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83490);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id(
    "CVE-2014-0230",
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-7810",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206",
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    71934,
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942,
    73225,
    73227,
    73231,
    73232,
    73237,
    73239,
    74475
  );
  script_osvdb_id(
    116423,
    116790,
    116791,
    116792,
    116793,
    116794,
    116795,
    116796,
    118817,
    119328,
    119755,
    119756,
    119757,
    119761,
    120539
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Apache Tomcat 6.0.x < 6.0.44 Multiple Vulnerabilities (FREAK)");
  script_summary(english:"Checks the Apache Tomcat Version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service listening on the remote host is 6.0.x prior to 6.0.44. It is,
therefore, affected by multiple vulnerabilities :

  - An error exists due to a failure to limit the size of
    discarded requests. A remote attacker can exploit this
    to exhaust available memory resources, resulting in a
    denial of service condition. (CVE-2014-0230)

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A NULL pointer dereference flaw exists with
    dtls1_get_record() when handling DTLS messages. A remote
    attacker, using a specially crafted DTLS message, can
    cause a denial of service. (CVE-2014-3571)

  - A flaw exists with ECDH handshakes when using an ECDSA
    certificate without a ServerKeyExchange message. This
    allows a remote attacker to trigger a loss of forward
    secrecy from the ciphersuite. (CVE-2014-3572)

  - A malicious application can use expression language to
    bypass the internal Security Manager and execute code
    with elevated privileges. (CVE-2014-7810)

  - A flaw exists when accepting non-DER variations of
    certificate signature algorithms and signature encodings
    due to a lack of enforcement of matches between signed
    and unsigned portions. A remote attacker, by including
    crafted data within a certificate's unsigned portion,
    can bypass fingerprint-based certificate-blacklist
    protection mechanisms. (CVE-2014-8275)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A flaw exists when accepting DH certificates for client
    authentication without the CertificateVerify message.
    This allows a remote attacker to authenticate to the
    service without a private key. (CVE-2015-0205)

  - A memory leak occurs in dtls1_buffer_record()
    when handling a saturation of DTLS records containing
    the same number sequence but for the next epoch. This
    allows a remote attacker to cause a denial of service.
    (CVE-2015-0206)

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

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

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/tomcat-6.0-doc/changelog.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/May/33");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191200");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1603781");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");
tomcat_check_version(fixed:"6.0.44", min:"6.0.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");
