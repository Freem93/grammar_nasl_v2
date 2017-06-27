#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67120);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2013-4882");
  script_bugtraq_id(61421);
  script_osvdb_id(95192);
  script_xref(name:"EDB-ID", value:"26807");
  script_xref(name:"IAVA", value:"2013-A-0117");
  script_xref(name:"MCAFEE-SB", value:"SB10043");

  script_name(english:"McAfee ePO Extension for McAfee Agent Multiple Blind SQL Injection (SB10043)");
  script_summary(english:"Checks extension version number");

  script_set_attribute(attribute:"synopsis", value:
"A security management application installed on the remote Windows host
has a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of ePO
Extension for McAfee Agent installed on the remote host has multiple
blind SQL injection vulnerabilities. A remote, authenticated user
could exploit this to execute arbitrary SQL queries, resulting in
arbitrary code execution with SYSTEM privileges.

Versions 4.5 and 4.6 of the extension are affected.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/80");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10043");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB78824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ePO Extension for McAfee Agent version 4.8 or later, or
apply the hotfix for version 4.6 referenced in McAfee Security
Bulletin SB10043.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

epo_path = get_kb_item_or_exit('SMB/mcafee_epo/Path'); # ePO install path
if (epo_path[strlen(epo_path) - 1] != "\") # add a trailing backslash if necessary
  epo_path += "\";

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# first, figure out where the mcafee agent extension is installed
config_path = strcat(epo_path, "Server\conf\Catalina\localhost\EPOAGENTMETA.xml");
xml_share = hotfix_path2share(path:config_path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:xml_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, xml_share);
}

agent_path = NULL;
xml = substr(config_path, 2); # strip the drive from the path
fh = CreateFile(
  file:xml,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  size = GetFileSize(handle:fh);
  if (size > 1024) size = 1024; # this file should be well under 1k
  data = ReadFile(handle:fh, length:size, offset:0);
  CloseFile(handle:fh);

  # determine where the extension is installed
  # <Context docBase="C:/Program Files/McAfee/ePolicy Orchestrator/Server/extensions/installed/EPOAGENTMETA/4.6.0.295/webapp"
  match = eregmatch(string:data, pattern:'docBase="([^"]+)"');
  if (!isnull(match))
  {
    agent_path = match[1] - 'webapp';
    agent_path = str_replace(string:agent_path, find:'/', replace:"\");
  }
}

if (isnull(agent_path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, 'McAfee ePO Extension for the McAfee Agent');
}

# now that it has been determined where the extension is installed,
# figure out which version it is
prop_share = hotfix_path2share(path:agent_path);
if (xml_share != prop_share)
{
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:prop_share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, prop_share);
  }
}

prop_file = substr(agent_path, 2) + 'extension.properties'; # strip out the drive from the pathname
agent_version = NULL;
fh = CreateFile(
  file:prop_file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  size = GetFileSize(handle:fh);
  if (size > 1024) size = 1024; # this file should be well under 1k
  data = ReadFile(handle:fh, length:size, offset:0);
  CloseFile(handle:fh);

  # sanity check - make sure that this extension actually is the epo extension for mcafee agent
  if (data =~ "extension\.name\s*=\s*EPOAGENTMETA")
  {
    match = eregmatch(string:data, pattern:"extension\.version\s*=\s*([\d.]+)");
    if (!isnull(match))
      agent_version = match[1];
  }
}

NetUseDel();

if (isnull(agent_version))
  audit(AUDIT_NOT_INST, 'McAfee ePO Extension for the McAfee Agent');

if (
  agent_version =~ "^4\.5\." ||
  (agent_version =~ "^4\.6\." && ver_compare(ver:agent_version, fix:'4.6.0.384', strict:FALSE) < 0)
)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + agent_path +
      '\n  Installed version : ' + agent_version +
      '\n  Fixed version     : 4.6.0.384 (4.6 hotfix) / 4.8\n';
    security_hole(port:port, extra:report);
  }
  else
  {
    security_hole(port);
  }
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, 'McAfee ePO Extension for the McAfee Agent', agent_version);
}

