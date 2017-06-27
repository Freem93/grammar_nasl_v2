#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68928);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/11 15:46:02 $");

  script_cve_id("CVE-2011-5124");
  script_bugtraq_id(47618);
  script_osvdb_id(72095);

  script_name(english:"Blue Coat Authentication and Authorization Agent Remote Overflow");
  script_summary(english:"Checks version of BCAAA");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an authentication application installed that is
affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Blue Coat Authentication and Authorization Agent
installed on the remote Windows host is earlier than build 60258.  It
is, therefore, potentially affected by a stack-based buffer overflow
vulnerability when handling specially crafted TCP packets on port 16102. 
By exploiting this flaw, a remote, unauthenticated attacker could
execute arbitrary code on the remote host subject to the privileges of
the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"https://kb.bluecoat.com/index?page=content&id=SA55");
  script_set_attribute(attribute:"solution", value:"Upgrade to build 60258 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Blue Coat Authentication and Authorization Agent (BCAAA) 5 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bluecoat:proxysg");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("bluecoat_auth_agent_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/BCAAA/Path", "SMB/BCAAA/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

app = 'Blue Coat Authentication and Authorization Agent';
version = get_kb_item_or_exit('SMB/BCAAA/Version');
path = get_kb_item_or_exit('SMB/BCAAA/Path');

if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/BCAAA');
  if (status != SERVICE_ACTIVE)
    exit(0, 'The '+app+' service is installed but not active.');
}

ver = split(version, sep:'.', keep:FALSE);
# Make sure the version has the build number
if (max_index(ver) < 5) exit(1, 'Failed to get the build number of ' + app);

for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (
    (ver[0] == 4 && ver[1] == 2 && ver[2] == 3) ||
    (ver[0] == 4 && ver[1] == 3) ||
    (ver[0] == 5 &&
      (ver[1] == 2 || ver[1] == 3 || ver[1] == 4 || ver[1] == 5)
    ) ||
    (ver[0] == 6 && ver[1] == 1)
  ) && ver[4] < 60258
)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3] +
      '\n  Installed build   : ' + ver[4] +
      '\n  Fixed build       : 60258\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
