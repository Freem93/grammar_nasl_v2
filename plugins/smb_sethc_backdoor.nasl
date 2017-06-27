#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73026);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"sethc.exe Possible Backdoor");
  script_summary(english:"Checks file metadata for sethc.exe");

  script_set_attribute(attribute:"synopsis", value:"A possible backdoor exists on the remote host.");
  script_set_attribute(attribute:"description", value:
"The copy of 'sethc.exe' in the Windows 'System32' directory on the
remote host appears to have been modified, perhaps for use as a
backdoor. Either or both of the 'InternalName' or 'OriginalFilename'
file attributes no longer match the original file.

This file is part of the Windows 'Sticky Keys' functionality and is
launched with SYSTEM privileges from a login screen when a Shift key
is pressed several times. After replacing the original file with, for
example, cmd.exe, an attacker with access to the host can bypass
authentication and gain a command shell and, in turn, complete control
of the host.");
  # http://www.explorehacking.com/2011/02/setting-backdoor-in-windows-command.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6f7d42f");
  script_set_attribute(attribute:"solution", value:
"Verify the contents of the 'sethc.exe' file and, if appropriate,
whether the system has been compromised.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

winroot = hotfix_get_systemroot();
if (isnull(winroot)) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:winroot);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\sethc.exe", string:winroot);
file_path = str_replace(string:share, find:"$", replace:":") + exe;

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
  NetUseDel();
  exit(1, "Failed to open '"+file_path+"'.");
}

internal_name = NULL;
original_filename = NULL;

ret = GetFileVersionEx(handle:fh);
if (!isnull(ret)) children = ret['Children'];

if (!isnull(children))
{
  varfileinfo = children['VarFileInfo'];
  if (!isnull(varfileinfo))
  {
    translation =
     (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
      get_word (blob:varfileinfo['Translation'], pos:2);
    translation = tolower(convert_dword(dword:translation, nox:TRUE));
  }
  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo) && !isnull(translation))
  {
    data = stringfileinfo[translation];
    if (isnull(data)) data = stringfileinfo[toupper(translation)];
    # Get InternalName and OriginalFilename
    if (!isnull(data))
    {
      if (!isnull(data['InternalName']))
        internal_name = tolower(data['InternalName']);
      if (!isnull(data['OriginalFilename']))
        original_filename = tolower(data['OriginalFilename']);
    }
  }
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(internal_name) && isnull(original_filename))
  exit(1, "Unable to obtain 'InternalName' and 'OriginalFilename' from file " + file_path + ".");

# Check for matching names
if (
  (
    !isnull(internal_name) &&
    internal_name != "sethc.exe" &&
    internal_name != "sethc"
  )
  ||
  (
    !isnull(original_filename) &&
    original_filename != "sethc.exe" &&
    original_filename != "sethc"
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  File              : ' + file_path;

    if (!isnull(internal_name))
      report += '\n  Internal Name     : ' + internal_name;
    if (!isnull(original_filename))
      report += '\n  Original Filename : ' + original_filename;

    report += '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The file '"+file_path+"' appears to be unmodified.");
