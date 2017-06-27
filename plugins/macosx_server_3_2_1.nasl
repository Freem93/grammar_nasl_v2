#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77758);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/21 16:17:30 $");

  script_cve_id(
    "CVE-2014-0060",
    "CVE-2014-0061",
    "CVE-2014-0062",
    "CVE-2014-0063",
    "CVE-2014-0064",
    "CVE-2014-0065",
    "CVE-2014-0066",
    "CVE-2014-4406",
    "CVE-2014-4424"
  );
  script_bugtraq_id(
    65723,
    65724,
    65727,
    65719,
    65725,
    65731,
    65728,
    69918,
    69935
  );
  script_osvdb_id(
    103544,
    103545,
    103546,
    103547,
    103548,
    103549,
    103551,
    111658,
    111659
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-09-17-5");

  script_name(english:"Mac OS X : OS X Server < 3.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the OS X Server version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.9 host has a version of OS X Server installed
that is prior to version 3.2.1. It is, therefore, affected by the
following vulnerabilities :

  - Multiple vulnerabilities exist within the included
    PostgreSQL, the more serious of these allow remote code
    execution or denial of service. (CVE-2014-0060,
    CVE-2014-0061, CVE-2014-0062, CVE-2014-0063,
    CVE-2014-0064, CVE-2014-0065, CVE-2014-0066)

  - A cross-site scripting vulnerability exists within the
    Xcode Server. Using a specially crafted website, a
    remote attacker can exploit this to execute arbitrary
    code within the server / browser trust relationship.
    (CVE-2014-4406)

  - An SQL injection vulnerability exists in the Wiki Server
    due to the improper validation of SQL queries. A remote
    attacker can exploit this to inject or manipulate SQL
    queries on the back-end database. (CVE-2014-4424)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6448");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X Server version 3.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.9([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "3.2.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
