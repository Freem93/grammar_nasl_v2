#
# (C) Josh Zlatin-Amishav and Tenable Network Security, Inc.
# GPLv2
#

# Tenable grants a special exception for this plugin to use the library
# 'smb_func.inc'. This exception does not apply to any modified version of
# this plugin.
#

include("compat.inc");

if (description)
{
 script_id(21162);
 script_version("$Revision: 1.413 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

 script_name(english:"Spybot Search & Destroy Detection");
 script_summary(english:"Checks whether Spybot Search & Destroy is installed");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a spyware detection program installed on
it.");
 script_set_attribute(attribute:"description", value:
"The remote Windows host is running Spybot Search & Destroy, a privacy
enhancing application that can detect and remove spyware of different
kinds from your computer.");
 script_set_attribute(attribute:"see_also", value:"http://www.safer-networking.org/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/28");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:safer-networking:spybot_search_and_destroy");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2013 Josh Zlatin-Amishav and Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain	= kb_smb_domain();
port    = kb_smb_transport();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# First find where the executable is installed on the remote host
# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Determine where Spybot S&D is installed
# Old version of this plugin doesn't take into account newer installers that use GUID
key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Spybot - Search & Destroy_is1",
                     "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B4092C6D-E886-4CB2-BA68-FE5A88D31DE6}_is1");

path = NULL;
foreach key (key_list)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Inno Setup: App Path");
    if (!isnull(value))
    {
      path = value[1];
      break;
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path)) {
  NetUseDel();
  audit(AUDIT_NOT_INST, "Spybot - Search & Destroy");
}

# Get the file version / latest sigs.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SpybotSD.exe", string:path);
rules = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Updates\downloaded.ini", string:path);

NetUseDel(close:FALSE);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (r != 1) {
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
  exit(1, "Can't open " +  exe);
}

version = GetFileVersion(handle:fh);
CloseFile(handle:fh);
if (isnull(version))
{
  NetUseDel();
  exit(1, "Can't get file version for " + exe);
}

ver = version[0] + "." + version[1] + "." + version[2] + "." + version[3];

# Get release date info about the detection rules (includes.zip)
fh = CreateFile(
  file:rules,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(1, "Can't open " + rules);
}

length = GetFileSize(handle:fh);
contents = ReadFile(handle:fh, offset:0, length:length);
CloseFile(handle:fh);

if (isnull(contents))
{
  NetUseDel();
  exit(1, "Can't read " + rules);
}
NetUseDel();

section_name = "";
sigs_target_array = make_array();
sig_parsed = FALSE;
sig_target_date = "";
has_description = FALSE;
foreach line (split(contents, sep:'\n', keep:TRUE))
{
  item = eregmatch(pattern:'\\[([^\\]]+)\\]', string:line);
  if(!isnull(item[1]))
  {
     # detection rules don't have descriptions
     if(section_name != "" && sig_target_date != "" && !has_description)
       sigs_target_array[section_name] = sig_target_date;

     has_description = FALSE;
     section_name = item[1];
     sig_target_date = "";
  }
  if("Description" >< line)
    has_description = TRUE;

  if (section_name != "")
  {
    item = eregmatch(pattern:'ReleaseDate=([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])', string:line);
    if(!isnull(item[1]))
    {
      a = split(item[1], sep:"-", keep:0);
      sig_target_date = a[0] + a[1] + a[2];
      sig_parsed = TRUE;
    }
  }
}

set_kb_item(name:"SMB/SpybotSD/Installed", value:TRUE);
set_kb_item(name:"SMB/SpybotSD/version", value:ver);

# Generate report.
info = get_av_info("spybot");
if (isnull(info)) exit(1, "Failed to get Spybot Search & Destroy info from antivirus.inc.");

last_engine_version = info["includes.zip"];
last_engine_version = info["supplemental.zip"];
last_engine_version = info["includes.dialer.zip"];
last_engine_version = info["includes.hijackers.zip"];
last_engine_version = info["includes.iPhone.zip"];
last_engine_version = info["includes.keyloggers.zip"];
last_engine_version = info["includes.malware.zip"];
last_engine_version = info["includes.pups.zip"];
last_engine_version = info["includes.security.zip"];
last_engine_version = info["includes.spybots.zip"];
last_engine_version = info["includes.trojans.zip"];

report =  '\n  Version : ' + ver;

if (sig_parsed)
{
  set_kb_item(name:"SMB/SpybotSD/signatures_present", value:TRUE);
  report += '\n\n  Installed Detection Signatures :';
  foreach filename (keys(sigs_target_array))
  {
    dt_target = sigs_target_array[filename];
    dt_vendor = sigs_vendor_array[filename];

    dt_target_dis = substr(dt_target, 4, 5) + "/" + substr(dt_target, 6, 7) +
    "/" + substr(dt_target, 0, 3);

    if(!isnull(dt_vendor))
      dt_vendor_dis = substr(dt_vendor, 4, 5) + "/" + substr(dt_vendor, 6, 7) +
      "/" + substr(dt_vendor, 0, 3);

    set_kb_item(name:"SMB/SpybotSD/signatures_target/" + filename, value:dt_target_dis);

    report += '\n    Filename : ' + filename;
    report += '\n      Signature update date           : ' + dt_target_dis;
    if(!isnull(dt_vendor_dis))
      report += '\n      Latest available signature date : ' + dt_vendor_dis;
  }
}
else
  set_kb_item(name:"SMB/SpybotSD/signatures_present", value:FALSE);

# set kbs for vendor sigs
foreach filename (keys(sigs_vendor_array))
{
    dt_vendor = sigs_vendor_array[filename];
    dt_vendor_dis = substr(dt_vendor, 4, 5) + "/" + substr(dt_vendor, 6, 7) + "/" + substr(dt_vendor, 0, 3);
    set_kb_item(name:"SMB/SpybotSD/signatures_vendor/" + filename, value:dt_vendor_dis);
}

report += '\n';
if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);

exit(0);
