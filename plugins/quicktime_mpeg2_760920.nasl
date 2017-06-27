#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69422);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/15 16:37:17 $");

  script_cve_id("CVE-2009-0008");
  script_bugtraq_id(33393);
  script_osvdb_id(51531);

  script_name(english:"Apple QuickTime MPEG-2 Playback Component Code Execution");
  script_summary(english:"Checks for QuickTime MPEG2 component");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a media decoding application that contains a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a copy of the QuickTime MPEG-2 playback
component, a commercial add-on to QuickTime distributed by Apple.

The remote version of this software is vulnerable to a remote code
execution vulnerability. To exploit this flaw, an attacker would need
to entice a user to view or process a maliciously crafter move file.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3404");
  script_set_attribute(attribute:"solution", value:"Upgrade to bersion 7.60.92.0 of this component.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime_mpeg-2_playback_component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{12EAE4F0-8770-451C-B4AD-76B569678973}";

# - nb: this works for recent versions of Adobe Reader.
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
value = NULL;
if (!isnull(key_h))
{
   value = RegQueryValue(handle:key_h, item:"DisplayVersion");
   RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


NetUseDel();
if (isnull(value))
{
  exit(0, 'The QuickTime MPEG2 Compontent was not detected on this host.');
}

version = split(value[1], sep:'.', keep:FALSE);
if ( int(version[0]) == 0 ) exit(1, "Could not obtain the version of the software");
if ( int(version[0]) < 7 ||
     (int(version[0]) == 7 && int(version[1]) < 60) ||
     (int(version[0]) == 7 && int(version[1]) == 60 && int(version[2]) < 92 ) ) security_hole(port:kb_smb_transport(),
											      extra:'The remote version of the QuickTime MPEG2 component is ' + value[1]);

