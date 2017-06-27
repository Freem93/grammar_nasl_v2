#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71856);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2013-6450");
  script_bugtraq_id(64618);
  script_osvdb_id(101597);

  script_name(english:"OpenSSL 1.0.0 < 1.0.0l DTLS Security Bypass");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may be affected by a security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL 1.0.0 prior to 1.0.0l.  The OpenSSL library is, therefore,
reportedly affected by a security bypass vulnerability related to
handling DTLS processes."
  );
  # Release announce
  script_set_attribute(attribute:"see_also", value:"http://www.mail-archive.com/openssl-announce@openssl.org/msg00129.html");
  # CVE-2013-6450 git commit
  # http://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=2d64b51d20375dbf52ca9cd45b5fea9772605935
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04f65a6b");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.0l or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/13");
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

openssl_check_version(fixed:'1.0.0l', min:"1.0.0", severity:SECURITY_WARNING);
