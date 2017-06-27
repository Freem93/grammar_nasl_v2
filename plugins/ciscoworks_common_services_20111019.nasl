#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69495);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_cve_id("CVE-2011-3310");
  script_bugtraq_id(50284);
  script_osvdb_id(76565);
  script_xref(name:"IAVA", value:"2011-A-0148");

  script_name(english:"CiscoWorks Common Services Home Page Component Unspecified Shell Command Execution");
  script_summary(english:"Checks version of CiscoWorks");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by an
arbitrary shell command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CiscoWorks Common Services installed on the remote
Windows host is potentially affected by an arbitrary shell command
execution vulnerability. By exploiting this flaw, a remote,
authenticated attacker could execute arbitrary commands on the remote
host subject to the privileges of the user running the affected
application.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CiscoWorks Common Services 4.0 or apply the vendor-
supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20111019-cs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e077c30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ciscoworks_common_services");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ciscoworks_common_services_installed.nasl");
  script_require_keys("SMB/CiscoWorks Common Services/Path", "SMB/CiscoWorks Common Services/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("datetime.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

app = 'CiscoWorks Common Services';

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
version = get_kb_item_or_exit('SMB/'+app+'/Version');
path = get_kb_item_or_exit('SMB/'+app+'/Path');

ver = split(version, sep:'.');
for (i = 0; i < max_index(ver); i ++)
  ver[i] = int(ver[i]);

if (ver[0] < 4 || (ver[0] == 4 && ver[1] < 1))
{
  # Check the timestamp of dcrui.jar
  share = hotfix_path2share(path:path);
  jar = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\MDC\tomcat\webapps\cwhp\WEB-INF\lib\dcrui.jar", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  retx = FindFirstFile(pattern:jar);
  timestamp = retx[3][2];

  fixtimestamp = '';
  if (ver[0] < 4 && int(timestamp) < 1311829320) fixtimestamp= '1311829320';
  else if (ver[0] == 4 && int(timestamp) < 1309493280) fixtimestamp = '1309493280';
  if (fixtimestamp)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  File              : ' + (share - '$') + ':\\' + jar +
        '\n  File Timestamp    : ' + timestamp +
        '\n  Fixed Timestamp   : ' + fixtimestamp + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
