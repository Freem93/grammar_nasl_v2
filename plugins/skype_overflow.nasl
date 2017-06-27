#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20090);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/12/14 20:22:12 $");

 script_cve_id("CVE-2005-3265", "CVE-2005-3267");
 script_bugtraq_id(15190, 15192);
 script_osvdb_id(20306, 20307, 20308);

 script_name(english:"Skype < 1.4.0.84 Multiple Remote Overflows (credentialed check)");
 script_summary(english:"Checks for Skype Heap overflow for Windows");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Skype, a peer-to-peer, voice-over-IP
software.

The remote version of this software is vulnerable to a heap overflow
in the handling of its data structures. An attacker can exploit this
flaw by sending a specially crafted network packet to UDP or TCP ports
Skype is listening on.

Successful exploitation of this issue may result in a crash of the
Skype user client or code execution on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2005-03.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to skype version 1.4.0.84 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119, 189);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/26");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("audit.inc");

name = kb_smb_name();
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();





if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1)
  exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1);
}


key = "SOFTWARE\Skype\Phone";
item = "SkypePath";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:item);
  if (!isnull(value))
    dir = value[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (dir)
{
 share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:dir);

 r = NetUseAdd(share:share);
 if (r == 1)
 {
  file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:dir);
  handle = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(handle))
  {
    ver = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
  }

  if (!isnull(ver))
  {
    if ( (ver[0] < 1) ||
         (ver[0] == 1 && ver[1] < 4) ||
         (ver[0] == 1 && ver[1] == 4 && ver[2] == 0 && ver[3] < 84) )
      security_hole(0);
  }
 }
}

NetUseDel();
