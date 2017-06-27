#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77088);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2014-3505",
    "CVE-2014-3506",
    "CVE-2014-3507",
    "CVE-2014-3508",
    "CVE-2014-3509",
    "CVE-2014-3510",
    "CVE-2014-3511",
    "CVE-2014-3512",
    "CVE-2014-5139"
  );
  script_bugtraq_id(
    69075,
    69076,
    69077,
    69078,
    69079,
    69081,
    69082,
    69083,
    69084
  );
  script_osvdb_id(
    109891,
    109892,
    109893,
    109894,
    109895,
    109896,
    109897,
    109898,
    109902
  );

  script_name(english:"OpenSSL 1.0.1 < 1.0.1i Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server uses a version of
OpenSSL 1.0.1 prior to 1.0.1i. The OpenSSL library is, therefore,
affected by the following vulnerabilities :

  - A memory double-free error exists related to handling
    DTLS packets that allows denial of service attacks.
    (CVE-2014-3505)

  - An unspecified error exists related to handling DTLS
    handshake messages that allows denial of service attacks
    due to large amounts of memory being consumed.
    (CVE-2014-3506)

  - A memory leak error exists related to handling
    specially crafted DTLS packets that allows denial of
    service attacks. (CVE-2014-3507)

  - An error exists related to 'OBJ_obj2txt' and the pretty
    printing 'X509_name_*' functions which leak stack data,
    resulting in an information disclosure. (CVE-2014-3508)

  - An error exists related to 'ec point format extension'
    handling and multithreaded clients that allows freed
    memory to be overwritten during a resumed session.
    (CVE-2014-3509)

  - A NULL pointer dereference error exists related to
    handling anonymous ECDH cipher suites and crafted
    handshake messages that allow denial of service attacks
    against clients. (CVE-2014-3510)

  - An error exists related to handling fragmented
    'ClientHello' messages that could allow a
    man-in-the-middle attacker to force usage of TLS 1.0
    regardless of higher protocol levels being supported by
    both the server and the client. (CVE-2014-3511)

  - A buffer overflow error exists related to handling
    Secure Remote Password protocol (SRP) parameters having
    unspecified impact. (CVE-2014-3512)

  - A NULL pointer dereference error exists related to
    handling Secure Remote Password protocol (SRP) that
    allows a malicious server to crash a client, resulting
    in a denial of service. (CVE-2014-5139)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.1-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140806.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.1i or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");

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

openssl_check_version(fixed:'1.0.1i', min:"1.0.1", severity:SECURITY_HOLE);
