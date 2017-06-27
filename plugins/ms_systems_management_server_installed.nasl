#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62028);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Microsoft SMS/SCCM Installed");
  script_summary(english:"Checks for Microsoft SMS");

  script_set_attribute(attribute:"synopsis", value:
"A systems management application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Systems Management Server, also known as System Center
Configuration Manager, a systems management application, is installed
on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/systemcenter/bb545936.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:systems_management_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

port   = kb_smb_transport();
name   = kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
appname = 'Microsoft Systems Management Server';

registry_init();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\SMS\Setup\Installation Directory";

path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

exe = path + "\bin\i386\sitecomp.exe";
ver = hotfix_get_fversion(path:exe);
if (isnull(ver['value']))
{
  # Check the x64 directory
  exe = path + "\bin\x64\sitecomp.exe";
  ver = hotfix_get_fversion(path:exe);
}
if (isnull(ver['value']))
{
  hotfix_check_fversion_end();
  audit(AUDIT_UNINST, appname);
}
close_registry(close:FALSE);
ver = ver['value'];

# If it is SCCM 2007, check if R2 is installed
r2_2007 = FALSE;
if (ver[0] == 4)
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
  ctrl = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\inboxes\sitectrl.box\sitectrl.ct0", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    close_registry();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
    file:ctrl,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  fsize = GetFileSize(handle:fh);
  off = 0;
  if (fsize)
  {
    while (off <= fsize)
    {
      data = ReadFile(handle:fh, length:10240, offset:off);
      if (strlen(data) == 0) break;

      if ('PROPERTY <IsR2CapableRTM>' >< data)
      {
        r2_2007 = TRUE;
        break;
      }
      else off += 10240;
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();

if (ver[0] < 4 && ver[0] != 2) product = 'Systems Management Server';
else if (ver[0] == 2) product = 'Systems Management Server 2003';
else if (ver[0] == 4) product = 'System Center Configuration Manager 2007';
else if (ver[0] == 5) product = 'System Center Configuration Manager 2012';
else product = 'System Center Configuration Manager';

if ('System Center Configuration Manager 2007' >< product)
{
  if (r2_2007) product += ' R2';
  if (int(ver[0]) == 4 && int(ver[1]) == 0 && int(ver[2]) == 6487 && int(ver[3]) >= 2157)
  {
    if ('R2' >< product) product += '/R3';
    else product += ' R3';
  }
}

version = join(ver, sep:'.');
set_kb_item(name:"SMB/"+appname+"/Installed", value:TRUE);
set_kb_item(name:"SMB/"+appname+"/Path", value:path);
set_kb_item(name:"SMB/"+appname+"/Version", value:version);
set_kb_item(name:"SMB/"+appname+"/Product", value:product);

register_install(
  app_name:appname,
  path:path,
  version:version,
  extra:make_array('Product', product),
  cpe:"cpe:/a:microsoft:systems_management_server");

if (report_verbosity > 0)
{
  report =
    '\n  Product : ' + product +
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
