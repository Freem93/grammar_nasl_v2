#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80566);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/07 18:00:12 $");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204"
  );
  script_bugtraq_id(
    71934,
    71935,
    71936,
    71937,
    71939,
    71942
  );
  script_osvdb_id(
    116423,
    116792,
    116793,
    116794,
    116795,
    116796
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"OpenSSL 0.9.8 < 0.9.8zd Multiple Vulnerabilities (FREAK)");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server uses a version of
OpenSSL 0.9.8 prior to 0.9.8zd. The OpenSSL library is, therefore,
affected by the following vulnerabilities :

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
    and decrypt the traffic. (CVE-2015-0204)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-0.9.8-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8zd or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'0.9.8zd', min:"0.9.8", severity:SECURITY_WARNING);
