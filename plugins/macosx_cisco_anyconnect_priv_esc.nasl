#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70259);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2013-1130");
  script_bugtraq_id(62519);
  script_osvdb_id(97524);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue33619");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client 3.0.x / 3.1.x Local Privilege Escalation");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is vulnerable to privilege
escalation attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect 3.0.x or 3.1.x.  As
such, it is vulnerable to a local privilege escalation attack caused by
improper permissions on a library directory.  This issue could allow a
local attacker to execute arbitrary programs with elevated privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=30916");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-1130
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34812377");
  script_set_attribute(
    attribute:"solution",
    value:
"The vendor has not released a patch.  Consult the workaround provided
by the vendor."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("MacOSX/Cisco_AnyConnect/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = 'Cisco AnyConnect Mobility VPN Client';

kb_base = "MacOSX/Cisco_AnyConnect";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

# Vendor notes in Alert ID 30916 vuln are :
# 3.0 .0629, .1047, .2052, .3050, .3054, .4235, .5075, .5080, Base
# and vendor further notes in CSCue33619 :
# '1st Found-In 3.1(0)'
# Further, the latest versions at the time of this writing are :
# 3.0.11046
# 3.1.04066
# and so, with 'Software updates not available', everything
# currently released is considered vuln.
if (
  version =~ "^3\.0($|[^0-9])"
  ||
  (
    version =~ "^3\.1" &&
    (
      (ver_compare(ver:version, fix:'3.1', strict:FALSE) >= 0)
      &&
      (ver_compare(ver:version, fix:'3.1.04066', strict:FALSE) < 1)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See solution.\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
