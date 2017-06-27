#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17745);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2001-1141");
  script_bugtraq_id(3004);
  script_osvdb_id(853);

  script_name(english:"OpenSSL < 0.9.6b Predictable Random Generator");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an SSL-related vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is running a version
of OpenSSL that is earlier than 0.9.6b and allows remote attackers to
predict the output of the pseudo-random generator.");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.6b or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'0.9.6b', severity:SECURITY_WARNING);
