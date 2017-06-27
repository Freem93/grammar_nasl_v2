#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(93478);
  script_cvs_date("$Date: 2016/09/14 17:59:55 $");
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2012-3052");
  script_osvdb_id(85578);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua28747");

  script_name(english:"Cisco VPN Client 5.x < 5.0.07.0440 Untrusted Search Path DLL Privilege Escalation");
  script_summary(english:"Check the version.");

  script_set_attribute(attribute:"synopsis", value:
"The VPN client installed on the remote Windows host is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Cisco VPN client installed on the remote host
is 5.x prior to 5.0.07.0440. It is, therefore, affected by a flaw
related to loading dynamic link library (DLL) files due to searching
fixed paths that may not be trusted or under user control. A local
attacker can exploit this, via a trojan DLL injected into the search
path, to execute arbitrary code with elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCua28747");
  script_set_attribute(attribute:"solution", value:
"This software is no longer supported. Contact the vendor for options.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vpn_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_vpn_client_detect.nasl");
  script_require_keys("SMB/CiscoVPNClient/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

app = "Cisco VPN Client";

ver  = get_kb_item_or_exit("SMB/CiscoVPNClient/Version");
path = get_kb_item_or_exit("SMB/CiscoVPNClient/Path");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app);
if (ver !~ "^5\.") audit(AUDIT_NOT_INST, app + " 5.x");
if (
  ver == "5" ||
  ver == "5.0" ||
  ver == "5.0.07"
)
  audit(AUDIT_VER_NOT_GRANULAR, app, ver);

if (ver_compare(fix:'5.0.07.0440', ver:ver, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : See Solution.' +
      '\n'
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
