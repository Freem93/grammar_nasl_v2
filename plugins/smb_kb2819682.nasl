#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65692);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_cve_id("CVE-2013-1299");
  script_bugtraq_id(58713);
  script_osvdb_id(91696);

  script_name(english:"MS KB2819682: Security Updates for Microsoft Windows Store Applications");
  script_summary(english:"Checks version of wlcore.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a mail application installed that is potentially
affected by a mail spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB2819682. It may, therefore, be affected
by an email spoofing vulnerability. A remote attacker could exploit
this flaw to trick a user into visiting a malicious website.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2819682");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2832006");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2819682.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_mail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# The Windows Store apps are always installed in C:\Program Files\WindowsApps
programfiles = hotfix_get_programfilesdir();
share = hotfix_path2share(path:programfiles);

MAX_RECURSE = 1;

function _list_dir(basedir, level, dir_pat, file_pat)
{
  local_var contents, ret, subdirs, subsub;

  # nb: limit how deep we'll recurse.
  if (level > MAX_RECURSE) return NULL;

  subdirs = NULL;
  if (isnull(dir_pat)) dir_pat = "";
  ret = FindFirstFile(pattern:basedir + "\*" + dir_pat + "*");

  contents = make_list();
  while (!isnull(ret[1]))
  {
    if (file_pat && ereg(pattern:file_pat, string:ret[1], icase:TRUE))
      contents = make_list(contents, basedir+"\"+ret[1]);

    subsub = NULL;
    if ("." != ret[1] && ".." != ret[1] && level <= MAX_RECURSE)
      subsub  = _list_dir(basedir:basedir+"\"+ret[1], level:level+1, file_pat:file_pat);
    if (!isnull(subsub))
    {
      if (isnull(subdirs)) subdirs = make_list(subsub);
      else subdirs = make_list(subdirs, subsub);
    }
    ret = FindNextFile(handle:ret);
  }

  if (isnull(subdirs)) return contents;
  else return make_list(contents, subdirs);
}

# Returns the file version as a string, either from the KB or by
# calling GetFileVersion(). Assumes we're already connected to the
# correct share.
function get_file_version()
{
  local_var fh, file, ver, version;

  if (isnull(_FCT_ANON_ARGS[0])) return NULL;

  file = _FCT_ANON_ARGS[0];
  version = get_kb_item("SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")));
  if (isnull(version))
  {
    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
      if (!isnull(ver))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        set_kb_item(
          name:"SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")),
          value:version
        );
      }
    }
  }
  return version;
}

name   = kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
hcf_init = TRUE;

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

winapps = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WindowsApps", string:programfiles);
patched = FALSE;
files = _list_dir(basedir:winapps, level:0, dir_pat:'microsoft.windowscommunicationsapps', file_pat:'^wlcore\\.dll');

if (isnull(files) || max_index(files) == 0) exit(0, 'The host is not affected because Windows Mail is not installed.');
# Check for any wlcore.dll files that have been patched within the WindowsApps folder
highestver = '0.0.0.0';
foreach file (files)
{
  ver = get_file_version(file);
  # Track the highest version installed so we can report on it
  # if the host is vulnerable
  if (ver_compare(ver:ver, fix:highestver) >= 0)
    highestver = ver;

  if (ver_compare(ver:ver, fix:'17.0.1114.318') >= 0)
  {
    patched = TRUE;
    break;
  }
}

NetUseDel();

if (!patched)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + highestver +
      '\n  Fixed version     : 17.0.1114.318' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
