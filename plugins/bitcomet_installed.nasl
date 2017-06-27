#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20748);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_name(english:"BitComet Detection");
  script_summary(english:"Checks for BitComet");

 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the
remote Windows host.");
 script_set_attribute(attribute:"description", value:
"BitComet is installed on the remote host. BitComet is a freeware
peer-to-peer file sharing application for Windows.

Make sure the use of this program fits with your corporate security
policy.");
 script_set_attribute(attribute:"see_also", value:"http://www.bitcomet.com/");
 script_set_attribute(attribute:"solution", value:
"Deinstall this software if its use does not match your corporate
security policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Determine if it's installed.
key = "SOFTWARE\Classes\bctp\shell\open\command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) {
    # nb: the value may appear in quotes.
    exe = ereg_replace(pattern:'"(.+)"', replace:"\1", string:value[1]);
  }
  RegCloseKey(handle:key_h);
}


# If it is...
if (exe) {
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0, "cannot connect to the remote share");
  }

  version = NULL;
  fh = CreateFile(
    file:path,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh)) {
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
        translation = tolower(display_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (!isnull(data)) version = data['ProductVersion'];
      }
    }
    CloseFile(handle:fh);
  }

  # If the version number's available, save and report it.
  if (!isnull(version) && version =~ "^[0-9]+\.") {
    if (version =~ "\.$") version = substr(version, 0, strlen(version)-2);

    set_kb_item(name:"SMB/BitComet/Version", value: version);

    if (report_verbosity)
    {
      report = string(
        "\n",
        "Version ", version, " of BitComet is installed as :\n",
        "\n",
        "  ", exe, "\n"
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
