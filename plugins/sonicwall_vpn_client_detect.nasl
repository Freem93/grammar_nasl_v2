#
# Script Written By Ferdy Riphagen
# Script distributed under the GNU GPLv2 License.
#
# Tenable grants a special exception for this plugin to use the library
# 'smb_func.inc'. This exception does not apply to any modified version of
# this plugin.
#
# Changes by Tenable :
# - Updated to use compat.inc (11/20/09)
# - Standardize vendor name in title / output (12/18/09)

include("compat.inc");

if (description) {
 script_id(29999);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

 script_set_attribute(attribute:"synopsis", value:"There is a VPN client installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The SonicWALL Global VPN Client is installed on the remote system.
This software can be used to establish secure remote connections.");
 script_set_attribute(attribute:"see_also", value:"http://www.sonicwall.com/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/18");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sonicwall:global_vpn_client");
script_end_attributes();

 script_name(english:"SonicWALL Global VPN Client Detection");
 script_summary(english:"Detects the presence and version of the SNWL Global VPN Client");

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2008-2015 Ferdy Riphagen");
 script_require_ports(139, 445);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/login", "SMB/password", "SMB/name", "SMB/transport");
 exit(0);
}

include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");

login = kb_smb_login();
pass = kb_smb_password();
port = kb_smb_transport();
name = kb_smb_name();
domain = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
ipc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (ipc != 1) {
	NetUseDel();
	exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
	NetUseDel();
	exit(0);
}

path = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\SWGVpnClient.exe";
regopen = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(regopen)) {
 	value = RegQueryValue(handle:regopen, item:"Path");
	RegCloseKey(handle:regopen);
	RegCloseKey(handle:hklm);
	if(!isnull(value)) path = value[1];
}
if (isnull(path)) {
	RegCloseKey(handle:hklm);
	NetUseDel();
	exit(0);
}
NetUseDel(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SWGVpnClient.exe", string:path);

conn = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (conn != 1) {
	NetUseDel();
	exit(0);
}

fopen = CreateFile(
	file:exe,
        desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING
);

if (isnull(fopen)) {
	NetUseDel();
	exit(0);
}

ret = GetFileVersion(handle:fopen);
CloseFile(handle:fopen);
NetUseDel();

if (!isnull(ret))
{
	ver = string(ret[0] + '.' + ret[1] + '.' + ret[2] + '.' + ret[3]);

	set_kb_item(name:"SMB/SonicWallGlobalVPNClient/Version", value:ver);
	set_kb_item(name:"SMB/SonicWallGlobalVPNClient/Path", value:path);

	report = string("\n",
			"Version ", ver, " of the SonicWall Global VPN Client is installed\n",
                        "under :\n",
                        "\n",
                        "  ", path
	);
	security_note(port:port, extra:report);
}
exit(0);
