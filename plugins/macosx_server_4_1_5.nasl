#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85410);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/21 16:17:30 $");

  script_cve_id("CVE-2015-5477");
  script_bugtraq_id(76092);
  script_osvdb_id(125438);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-08-13-4");

  script_name(english:"Mac OS X : OS X Server < 4.1.5 BIND DoS");
  script_summary(english:"Checks the OS X Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of OS X Server installed that
is prior to 4.1.5. It is, therefore, affected by a denial of service
vulnerability due to an assertion flaw that occurs when handling TKEY
queries. A remote attacker can exploit this, via a specially crafted
request, to cause a REQUIRE assertion failure and daemon exit,
resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205032");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OS X Server version 4.1.5 or later.

Note that OS X Server 4.1.5 is available only for OS X 10.10.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
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

fixed_version = "4.1.5";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
