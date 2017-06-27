#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53916);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"PsExec Service Installed");
  script_summary(english:"Checks for psexesvc.exe");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a remote control service installed.");

  script_set_attribute(attribute:"description", value:
"The PsExec service, a tool that allows remote control of the system,
is installed on the remote Windows host.");

  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/sysinternals/bb897553");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_family(english:"Windows");
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, 'Can\'t get the Windows system root.');

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:rootfile);

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

info = '';
count = 0;

foreach root (make_list(rootfile, rootfile + '\\system32'))
{
  path = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1', string:root);
  exe = path + '\\psexesvc.exe';

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    if (isnull(ver)) version = 'unknown';
    else version = join(sep:'.', ver);

    set_kb_item(name:'SMB/PSExec/'+root+'/Version', value:version);
    info +=
      '\n  File    : ' + root + '\\psexesvc.exe' +
      '\n  Version : ' + version + '\n';
    count++;
  }
}

NetUseDel();

if (count > 0)
{
  if (report_verbosity > 0)
  {
    if (count > 1) s = 's of the PsExec service were found';
    else s = ' of the PsExec service was found';

    report =
      '\n  The following version' + s + ' on the remote host : ' +
      info;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, 'The PsExec service wasn\'t detected on the remote host.');
