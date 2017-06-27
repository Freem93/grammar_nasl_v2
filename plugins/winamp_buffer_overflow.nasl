#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Sat, 4 Jan 2003 05:00:47 -0800
#  From: D4rkGr3y <grey_1999@mail.ru>
#  To: bugtraq@securityfocus.com, submissions@packetstormsecurity.com,
#        vulnwatch@vulnwatch.org
#  Subject: [VulnWatch] WinAmp v.3.0: buffer overflow



include("compat.inc");

if (description)
{
 script_id(11530);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/11/02 20:50:26 $");
 script_cve_id("CVE-2003-1272", "CVE-2003-1273", "CVE-2003-1274");
 script_bugtraq_id(6515, 6516, 6517);
 script_osvdb_id(34427, 34428, 34429);

 script_name(english:"Winamp < 3.0b Multiple File Handling DoS");
 script_summary(english:"Determines the version of Winamp");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp3, a popular media player which handles
many files format (mp3, wavs and more...)

This version suffers from multiple buffer overflow and denial of
service issues that can be triggered by specially crafted b4s files.
To perform an attack, the attack would have to send a malformed
playlist (.b4s) to the user of this host who would then have to load
it by double clicking on it.

Note that since .b4s are XML-based files, most antivirus programs will
let them in.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jan/27");
 script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?postid=823240" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 3.0b or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/14");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
winamp3 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinAmp3\studio.exe", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();





if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:winamp3, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( !isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 if ( isnull(version) )
 {
  NetUseDel();
  exit(1);
 }

 if ( version[0] == 1 && version[1] == 0 && version[2] == 0 && version[3] <= 488 )
	security_hole(port);

 CloseFile(handle:handle);
}


NetUseDel();
