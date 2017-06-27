#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17798);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-1999-0428");
  script_bugtraq_id(82466);
  script_osvdb_id(3936);

  script_name(english:"OpenSSL < 0.9.2b Session Reuse");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an SSL session reuse attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.2b. 

A remote attacker could reuse an SSL session under a different context
and bypass access control mechanisms based on client certificates.");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Mar/144");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 0.9.8s or later as the 0.9.2 branch is no longer
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"1999/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");

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

openssl_check_version(fixed:'0.9.2b', severity:SECURITY_HOLE);
