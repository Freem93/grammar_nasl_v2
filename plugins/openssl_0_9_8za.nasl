#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74363);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(66363, 67898, 67899, 67900, 67901);
  script_osvdb_id(104810, 107729, 107730, 107731, 107732);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"OpenSSL 0.9.8 < 0.9.8za Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server uses a version of
OpenSSL 0.9.8 prior to 0.9.8za. The OpenSSL library is, therefore,
reportedly affected by the following vulnerabilities :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that could lead to execution of
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

  - An error exists related to DTLS handshake handling that
    could lead to denial of service attacks. Note this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0076");
  #  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0195");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0221");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-3470");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"http://ccsinjection.lepidum.co.jp/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8za or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'0.9.8za', min:"0.9.8", severity:SECURITY_HOLE);
