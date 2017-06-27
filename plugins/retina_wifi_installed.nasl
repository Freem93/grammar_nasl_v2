#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39808);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"eEye Retina Wireless Scanner (Standalone) Detection");
  script_summary(english:"Checks the registry for a Retina WiFi install");

  script_set_attribute(attribute:"synopsis", value:"A wireless network scanner is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Retina Wireless Scanner is installed on the remote host.

This program is currently installed as a standalone application.
Please note it is no longer distributed in this manner, and is now
included with Retina Network Security Scanner.");
  script_set_attribute(attribute:"see_also", value:"http://download.eeye.com/html/products/retinawireless/");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.eeye.com/html/products/retina/index.html"
  );
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this software is in agreement with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("misc_func.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");


# This is virtually identical to GetFileVersionEx() in smb_file.inc.
# The only difference is a check for a section called 'sectio%n' rather than
# '.rsrc'.  I'll include this in here for now until I can verify this is the
# only difference.
function get_exe_ver_ex(handle)
{
 local_var dos_header, sig, e_lfanew, nt_header, number_of_sections, size_optional_header, i;
 local_var offset, size, sections, pos, idx, tmp, pattern, rsrc, r_pattern, ret, name, voffset;
 local_var __sections, section;

 # We first parse IMAGE_DOS_HEADER
 dos_header = ReadFile (handle:handle, offset:0, length:64);
 if (!dos_header || (strlen(dos_header) != 64))
   return NULL;

 sig = substr(dos_header, 0, 1);
 if ("MZ" >!< sig)
   return NULL;

 e_lfanew = get_dword (blob:dos_header, pos:60);


 # We now parse Signature + IMAGE_FILE_HEADER
 nt_header = ReadFile (handle:handle, offset:e_lfanew, length:24);
 if (!nt_header || (strlen(nt_header) != 24))
   return NULL;

 sig = substr(nt_header, 0, 1);
 if ("PE" >!< sig)
   return NULL;

 number_of_sections = get_word (blob:nt_header, pos:6);
 size_optional_header = get_word (blob:nt_header, pos:20);


 # We now parse sections
 offset = e_lfanew + 24 + size_optional_header;
 size = number_of_sections * 40;
 sections = ReadFile (handle:handle, offset:offset, length:size);
 if (!sections || (strlen(sections) != size))
   return NULL;

 pos = rsrc = 0;
 r_pattern = "sectio%n";

 __sections = NULL;
 for (i=0; i<number_of_sections; i++)
 {
  section = make_list (
        substr(sections, pos, pos+7),                     # name
        get_dword (blob:sections, pos:pos+16),            # size
        get_dword (blob:sections, pos:pos+20),            # offset
        get_dword (blob:sections, pos:pos+12)             # voffset
        );

  if (r_pattern >< section[0])
  {
   rsrc = 1;
   offset = section[2];
   size = section[1];
  }

  __sections[i] = section;

  pos += 40;
 }

 # if no rsrc section left
 if (rsrc == 0)
   return NULL;

 return check_version (size:size, offset:offset, sections:__sections, handle:handle);
}

# wrapper for function above
function get_exe_ver(handle)
{
 local_var ret, tmp;

 ret = get_exe_ver_ex(handle:handle);
 if (isnull(ret))
   return NULL;

 tmp = NULL;
 tmp[0] = ret['dwFileVersionMS'] >>> 16;
 tmp[1] = ret['dwFileVersionMS'] & 0xFFFF;
 tmp[2] = ret['dwFileVersionLS'] >>> 16;
 tmp[3] = ret['dwFileVersionLS'] & 0xFFFF;

 return tmp;
}

#
# Execution starts here
#

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "Remote registry has not been enumerated.");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# The latest installer doesn't put path info HKLM\Software\eEye, and it's
# unclear if earlier versions did.  Instead we'll check to see if it's
# in the default dir created by the latest installer
path = hotfix_get_programfilesdir();
if (!path) exit(1, "Can't determine Program Files directory.");

share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

path = path + "\eEye Digital Security\Retina Wireless Scanner";
exe = ereg_replace(
  pattern:'^[A-Za-z]:(.*)',
  replace:"\1\RetinaWireless.exe",
  string:path
);

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Grab the version number if the file was opened successfully.  Otherwise,
# bail out.
ver = NULL;
if (fh)
{
  ver = GetFileVersion(handle:fh);

  # GetFileVersion() looks for version in the '.rsrc' section. It appears the
  # latest exe has version in a section called 'sectio%n'. Unclear how many
  # versions back this has been the case.
  if (isnull(ver)) ver = get_exe_ver(handle:fh);

  CloseFile(handle:fh);
  NetUseDel();
}
else
{
  NetUseDel();
  exit(0, "Unable to access Retina file: " + exe);
}

if (ver)
{
  wifi_ver = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
  set_kb_item(name:"SMB/RetinaWiFi/Version", value:wifi_ver);
  set_kb_item(name:"SMB/RetinaWiFi/" + wifi_ver, value:path);

  register_install(
    app_name:"eEye Retina Wireless Scanner (Standalone)",
    path:path,
    version:wifi_ver);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Install Path : ", path, "\n",
      "Version      : ", wifi_ver, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(1, "Error retrieving version number from Retina file: " + exe);
