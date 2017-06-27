#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20845);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_name(english:"BitLord Detection");
  script_summary(english:"Checks for BitLord");

 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the
remote Windows host.");
 script_set_attribute(attribute:"description", value:
"BitLord is installed on the remote Windows host. BitLord is a freeware
peer-to-peer file sharing application that supports the BitTorrent
protocol.

Make sure the use of this program fits with your corporate security
policy.");
 script_set_attribute(attribute:"see_also", value:"http://www.bitlord.com/");
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/04");

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
  exit(0, "cannot connect to the remote registry");
}


# Determine if it's installed.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\BitLord.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) exe = value[1];
  RegCloseKey(handle:key_h);
}
if (isnull(exe) && thorough_tests) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BitLord\DisplayIcon";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:"DisplayIcon");
    if (!isnull(value)) exe = value[1];
    RegCloseKey(handle:key_h);
  }
}
if (isnull(exe) && thorough_tests) {
  key = "SOFTWARE\Classes\bittorrent\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value) && "bittorrent.exe" >!< tolower(value[1])) {
      # nb: the exe itself appears in quotes.
      exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# If it is...
if (exe) {
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0, "cannot connect to the remote share");
  }

  fh = CreateFile(
    file:exe2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  version = NULL;
  if (!isnull(fh)) {
    # nb: GetFileVersion returns more detail than the product
    #     version; eg, "1.1.5.6" versus "1.1"
    ver = GetFileVersion(handle:fh);
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
    CloseFile(handle:fh);
  }

  # If the version number's available, save and report it.
  if (!isnull(version)) {
    set_kb_item(name:"SMB/BitLord/Installed", value:TRUE);
    set_kb_item(name:"SMB/BitLord/Version", value:version);

    if (report_verbosity)
    {
      report = string(
        "\n",
        "BitLord version ", version, " is installed as :\n",
        "  ", exe, "\n"
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}


# Clean up.
NetUseDel();
