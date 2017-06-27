#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84151);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/01 13:42:18 $");

  script_cve_id(
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792"
  );
  script_bugtraq_id(
    75154,
    75156,
    75157,
    75158,
    75161
  );

  script_name(english:"OpenSSL 0.9.8 < 0.9.8zg Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server uses a version of
OpenSSL 0.9.8 prior to 0.9.8zg. The OpenSSL library is, therefore,
affected by the following vulnerabilities :

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the
    ASN1_TIME string by the X509_cmp_time() function. A
    remote attacker can exploit this, via a malformed
    certificate and CRLs of various sizes, to cause a
    segmentation fault, resulting in a denial of service
    condition. TLS clients that verify CRLs are affected.
    TLS clients and servers with client authentication
    enabled may be affected if they use custom verification
    callbacks. (CVE-2015-1789)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing inner
    'EncryptedContent'. This allows a remote attacker, via
    specially crafted ASN.1-encoded PKCS#7 blobs with
    missing content, to cause a denial of service condition
    or other potential unspecified impacts. (CVE-2015-1790)

  - A double-free error exists due to a race condition that
    occurs when a NewSessionTicket is received by a
    multi-threaded client when attempting to reuse a
    previous ticket. (CVE-2015-1791)

  - A denial of service vulnerability exists in the CMS code
    due to an infinite loop that occurs when verifying a
    signedData message. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-1792)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 0.9.8gz or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'0.9.8zg', min:"0.9.8", severity:SECURITY_WARNING);
