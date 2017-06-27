#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64620);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2013-0169");
  script_bugtraq_id(57778);
  script_osvdb_id(89848);

  script_name(english:"OpenSSL 1.0.1 < 1.0.1e Information Disclosure");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote service may be affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version of
OpenSSL 1.0.1 prior to 1.0.1e.  The OpenSSL library is, therefore,
reportedly affected by an incomplete fix for CVE-2013-0169.

An error exists related to the SSL/TLS/DTLS protocols, CBC mode
encryption and response time.  An attacker could obtain plaintext
contents of encrypted traffic via timing attacks."
  );
  # http://www.mail-archive.com/openssl-announce@openssl.org/msg00125.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?109aacf1");
  # http://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=0c4b72e9c0e3a75e0b89166540396dc3b58138b8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726376ef");
  # http://git.openssl.org/gitweb/?p=openssl-web.git;a=commitdiff;h=3668d99f1db0410ccd43b5edb88651ccf6e9ac48
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8275c125");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.1e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");

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

openssl_check_version(fixed:'1.0.1e', min:"1.0.1", severity:SECURITY_NOTE);
