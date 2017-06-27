#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64476);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id("CVE-2013-0156", "CVE-2013-0333");
  script_bugtraq_id(57187, 57575);
  script_osvdb_id(89026, 89594);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-04-1");

  script_name(english:"Mac OS X : OS X Server < 2.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks OS X Server version.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing an update for OS X Server that fixes two
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.8 host has a version of OS X Server installed
that is prior to 2.2.1. It is, therefore, affected by the following
vulnerabilities :

  - A type casting issue exists in Ruby on Rails due to
    improper handling of XML parameters. A remote attacker
    can exploit this issue to execute arbitrary code through
    either the Profile Manager or Wiki Server components.
    (CVE-2013-0156)

  - A type casting issue exists in Ruby on Rails due to
    improper handling of JSON data. A remote attacker can
    exploit this to execute arbitrary code through the
    Wiki Server component. (CVE-2013-0333)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5644");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525572/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X Server v2.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails JSON Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "2.2.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
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
