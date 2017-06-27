#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64534);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2012-2686", "CVE-2013-0166", "CVE-2013-0169");
  script_bugtraq_id(57755, 57778, 60268);
  script_osvdb_id(89848, 89849, 89865, 89866);

  script_name(english:"OpenSSL 1.0.1 < 1.0.1d Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL 1.0.1 prior to 1.0.1d.  The OpenSSL library is, therefore, 
reportedly affected by the following vulnerabilities :

  - An error exists related to AES-NI, TLS 1.1, TLS 1.2 and
    the handling of CBC ciphersuites that could allow denial
    of service attacks. Note that platforms and versions
    that do not support AES-NI, TLS 1.1, or TLS 1.2 are not
    affected. (CVE-2012-2686)

  - An error exists related to the handling of OCSP response
    verification that could allow denial of service attacks.
    (CVE-2013-0166)

  - An error exists related to the SSL/TLS/DTLS protocols,
    CBC mode encryption and response time. An attacker
    could obtain plaintext contents of encrypted traffic via
    timing attacks. (CVE-2013-0169)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20130204.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.1d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.1d', min:"1.0.1", severity:SECURITY_WARNING);
