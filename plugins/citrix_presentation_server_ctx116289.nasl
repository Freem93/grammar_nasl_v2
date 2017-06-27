#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69129);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_cve_id("CVE-2008-2299", "CVE-2008-2300");
  script_bugtraq_id(29232, 29233);
  script_osvdb_id(45328, 45329);

  script_name(english:"Citrix Presentation Server 4.5 Multiple Vulnerabilities");
  script_summary(english:"Checks timestamp of 'ctxadmin.dll'");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Presentation Server installed on the remote
Windows host is potentially affected by multiple vulnerabilities :

  - The application can cause clients to use weaker
    encryption settings than configured by the
    administrator, which could allow attackers to bypass
    intended restrictions. (CVE-2008-2299)

  - It is possible for remote, authenticated users to access
    unauthorized desktops via unknown attack vectors.
    (CVE-2008-2300)");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX116289");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the Citrix advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:presentation_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

appname = 'Citrix Presentation Server';

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key =  "SOFTWARE\Citrix\Install\Location";
path = get_registry_value(handle:hklm, item:key);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\system32\ctxadmin.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  audit(AUDIT_UNINST, appname);
  NetUseDel();
}

vuln = FALSE;
ver = GetFileVersion(handle:fh);
if (isnull(ver))
{
  NetUseDel();
  audit(AUDIT_VER_FAIL, path + "\system32\ctxadmin.dll");
}
version = join(ver, sep:'.');
if (ver[0] < 4 || (ver[0] == 4 && ver[1] < 5))
{
  vuln = TRUE;
  CloseFile(handle:fh);
}
else if (ver[0] == 4 && ver[1] == 5)
{
  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);
  if (isnull(ret['dwTimeDateStamp']))
  {
    NetUseDel();
    exit(1, 'Failed to get the timestamp from ' + path + "\system32\ctxadmin.dll");
  }
  timestamp = ret['dwTimeDateStamp'];
  if (int(timestamp) < 1205775600)
  {
    vuln = TRUE;
    fixtimestamp = 1205775600;
  }
}
NetUseDel();

if (vuln)
{
  if (report_verbosity > 0)
  {
    if (!fixtimestamp)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 4.5\n';
    }
    else
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  File              : ' + path + "\system32\ctxadmin.dll" +
        '\n  File timestamp    : ' + timestamp +
        '\n  Fixed timestamp   : ' + fixtimestamp + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
