#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69515);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2012-0397");
  script_bugtraq_id(52315);
  script_osvdb_id(79894);
  script_xref(name:"IAVB", value:"2012-B-0027");

  script_name(english:"RSA SecurID Software Token Converter XML-Formatted .sdtid Buffer Overflow");
  script_summary(english:"Looks for the affected application by walking C:\Users");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that may be affected by a
buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"RSA SecurID Software Token Converter prior to version 2.6.1 is prone
to an overflow condition. A boundary error occurs when handling XML-
formatted '.sdtid' file strings. By tricking a user into running the
converter with a crafted file, an attacker could potentially execute
arbitrary code.");
  script_set_attribute(attribute:"solution", value:"Update to version 2.6.1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Mar/att-16/esa-2012-013.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:securid_software_token_converter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

# Will find files down to C:\Users\Tenable\Desktop\tools\TokenConverter.exe

function _list_dir(basedir, level, file_pat)
{
  local_var contents, ret, subdirs, subsub, MAX_RECURSE;
  MAX_RECURSE = 4;

  # nb: limit how deep we'll recurse.
  if (level > MAX_RECURSE) return NULL;

  subdirs = NULL;
  ret = FindFirstFile(pattern:basedir + "\*");

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

function get_profiles_dir()
{
  local_var hklm, pdir, root, share;

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pdir = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory");

  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    root = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot");
    if (!isnull(root))
    {
      share = hotfix_path2share(path:root);
      pdir = share - '$' + ':' + substr(pdir, strlen("%systemdrive%"));
    }
  }

  RegCloseKey(handle:hklm);
  close_registry();

  return pdir;
}

if (!thorough_tests)
  audit(AUDIT_THOROUGH);

profile_dir = get_profiles_dir();
if (isnull(profile_dir))
  exit(1, "Could not get ProfilesDirectory from the registry.");

# Split up the drive letter and the path
matches = eregmatch(pattern:"^([A-Za-z]):(.*)$", string:profile_dir);
if (isnull(matches[0]) || isnull(matches[1]) || isnull(matches[2]))
  exit(1, "Malformed path returned from registry query.");

drive = matches[1] + ":";
share = matches[1] + "$";
path = matches[2];

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

files = _list_dir(basedir:'\\Users', level:0, file_pat:"^TokenConverter[0-9]*\.exe$");

# This is the modification date of the first patched Windows version
fixtimestamp = 1326208282;
report = "";
audit_report = "";
vulnerable = FALSE;

foreach file (files)
{
  human_path = drive + file;

  handle = CreateFile(
             file:file,
             desired_access:GENERIC_READ,
             file_attributes:FILE_ATTRIBUTE_NORMAL,
             share_mode:FILE_SHARE_READ,
             create_disposition:OPEN_EXISTING
           );

  if (isnull(handle))
  {
    audit_report += "Could not open '" + human_path + '\'.\n';
    continue;
  }

  ver = GetFileVersionEx(handle:handle);
  CloseFile(handle:handle);

  if (isnull(ver) || isnull(ver["dwTimeDateStamp"]) || uint(ver["dwTimeDateStamp"]) == 0)
  {
    audit_report += "Could not get timestamp of '" + human_path + '\'.\n';
    continue;
  }

  timestamp = ver["dwTimeDateStamp"];

  if (uint(timestamp) >= uint(fixtimestamp))
  {
    audit_report += "'" + human_path + '\' is not vulnerable.\n';
    continue;
  }

  report += '\n  Path            : ' + human_path +
            '\n  File timestamp  : ' + timestamp +
            '\n  Fixed timestamp : ' + fixtimestamp + '\n';
  vulnerable = TRUE;
}

NetUseDel();

if (audit_report == "" && report == "")
  audit(AUDIT_NOT_INST, "RSA SecurID Software Token Converter");

if (!vulnerable)
  exit(0, audit_report);

security_hole(port:port, extra:report);
