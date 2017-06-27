#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71857);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2013-4353", "CVE-2013-6449", "CVE-2013-6450");
  script_bugtraq_id(64530, 64618, 64691);
  script_osvdb_id(101347, 101597, 101843);

  script_name(english:"OpenSSL 1.0.1 < 1.0.1f Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote service may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL 1.0.1 prior to 1.0.1f.  The OpenSSL library is, therefore,
reportedly affected by the following vulnerabilities :

  - An error exists in the 'ssl3_take_mac' function in the
    file 'ssl/s3_both.c' related to handling TLS handshake
    traffic that could lead to denial of service attacks.
    (CVE-2013-4353)

  - An error exists in the 'ssl_get_algorithm2' function in
    the file 'ssl/s3_lib.c' related to handling TLS 1.2
    traffic that could lead to denial of service attacks.
    (CVE-2013-6449)

  - An error exists related to man-in-the-middle attackers
    and handling DTLS processes that could lead to various
    security bypasses. (CVE-2013-6450)"
  );
  # Release announce
  script_set_attribute(attribute:"see_also", value:"http://www.mail-archive.com/openssl-announce@openssl.org/msg00128.html");
  # CVE-2013-4353 git commit
  # http://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=197e0ea817ad64820789d86711d55ff50d71f631
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93ad3533");
  # CVE-2013-6449 git commit
  # http://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ca98926
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81124091");
  # CVE-2013-6450 git commit
  # http://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=3462896
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4485220");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.1f or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/08");

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

openssl_check_version(fixed:'1.0.1f', min:"1.0.1", severity:SECURITY_WARNING);
