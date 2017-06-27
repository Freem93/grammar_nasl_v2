#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20865);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Songbird Detection");
  script_summary(english:"Checks for Songbird");

 script_set_attribute(attribute:"synopsis", value:"There is a media player installed on the remote Windows host.");
 script_set_attribute(attribute:"description", value:
"Songbird is installed on the remote host. Songbird is an open source
media player for Windows from the Songbird Project.

Make sure the use of this program fits with your corporate security
policy.");
 script_set_attribute(attribute:"see_also", value:"http://www.songbirdnest.com/");
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/09");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:songbird:songbird_media_player");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
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
  exit(0, "cannot connect to the remote registry");
}


# Determine if it's installed.
key = "SOFTWARE\Songbird";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(value)) path = value[1];
  else path = NULL;

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path) {
  # Locate Songbird's application.ini
  #
  # nb: the version here is much more detailed than the one found in,
  #     say, 'chrome/locale/en-US/rmp_demo.dtd'.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  ini =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\application.ini", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0, "cannot connect to the remote share");
  }

  fh = CreateFile(
    file:ini,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) {
    NetUseDel();
    exit(0, strcat("cannot read '", ini, "'"));
  }

  data = ReadFile(handle:fh, length:512, offset:0);
  if (data) {
    # Pull out version and build.
    foreach line (split(data, keep:FALSE)) {
      if ("Version=" >< line) version = ereg_replace(pattern:".*Version=(.+)", replace:"\1", string:line);
      else if ("BuildID=" >< line) build = ereg_replace(pattern:".*BuildID=(.+)", replace:"\1", string:line);

      if (!isnull(version) && !isnull(build)) {
        ver = string(version, " build ", build);
        break;
      }
    }
  }
  CloseFile(handle:fh);

  # If the version number's available, save and report it.
  if (!isnull(ver)) {
    set_kb_item(name:"SMB/Songbird/Version", value:ver);

    report = string(
      "Version ", ver, " of Songbird is installed in :\n",
      "  ", path, "\n"
    );

    security_note(port:kb_smb_transport(), extra:report);
  }
}


# Clean up.
NetUseDel();
