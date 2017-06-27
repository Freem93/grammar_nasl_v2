#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83088);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id("CVE-2014-3566", "CVE-2015-1150", "CVE-2015-1151");
  script_bugtraq_id(70574, 74355, 74356);
  script_osvdb_id(113251, 121283, 121284);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-04-24-1");

  script_name(english:"Mac OS X : OS X Server < 4.1 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Checks the OS X Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of OS X Server installed that
is prior 4.1. It is, therefore, affected by vulnerabilities in the
following components :

  - Dovecot
  - Firewall
  - Postfix
  - Wiki Server");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT204201");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OS X Server version 4.1 or later.

Note that OS X Server 4.1 is available only for OS X 10.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "4.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
