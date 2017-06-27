#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69136);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/09/04 15:20:59 $");

  script_bugtraq_id(47016);
  script_osvdb_id(72402);
  script_xref(name:"IAVB", value:"2011-B-0040");

  script_name(english:"Citrix Presentation Server 4.5 ActiveSync Feature Code Execution");
  script_summary(english:"Checks timestamp of ctxactivesync.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Presentation Server installed on the remote
Windows host is potentially affected by a code execution vulnerability
in the ActiveSync Feature.  By exploiting this flaw, a remote,
unauthenticated attacker could execute arbitrary code on the remote host
subject to the privileges of the user running the affected
application.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX128366");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:presentation_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
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
status = get_kb_item_or_exit('SMB/svc/CtxActiveSync');
if (status != SERVICE_ACTIVE) exit(0, 'The '+appname+' service is installed but not active.');

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
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\system32\CtxActiveSync.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
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
  audit(AUDIT_VER_FAIL, path + "\system32\CtxActiveSync.exe");
}
version = join(ver, sep:'.');
if (ver[0] == 4 && ver[1] == 5)
{
  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);
  if (isnull(ret['dwTimeDateStamp']))
  {
    NetUseDel();
    exit(1, 'Failed to get the timestamp from ' + path + "\system32\CtxActiveSync.exe");
  }
  timestamp = ret['dwTimeDateStamp'];
  if (int(timestamp) < 1307714640)
  {
    vuln = TRUE;
    fixtimestamp = 1307714640;
  }
}
NetUseDel();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  File              : ' + path + "\system32\CtxActiveSync.exe" +
      '\n  File timestamp    : ' + timestamp +
      '\n  Fixed timestamp   : ' + fixtimestamp + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
