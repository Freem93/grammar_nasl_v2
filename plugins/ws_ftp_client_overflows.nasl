#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12108);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:50 $");

 script_bugtraq_id(9872);
 script_osvdb_id(4305);
 script_xref(name:"Secunia", value:"11136");

 script_name(english:"WS_FTP Pro Client ASCII Mode Directory Listing Handling Overflow");
 script_summary(english:"IPSWITCH WS_FTP client overflow detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an FTP client that is prone to a buffer
overflow attack.");
 script_set_attribute(attribute:"description", value:
"The version of WS_FTP Pro, an FTP client, installed on the remote host
is earlier than 9.0. Such versions are reportedly affected by a remote
overflow triggered by an overly long string of ASCII mode directory
data from a malicious server.

If an attacker can trick a user on this system to connect to a
malicious FTP server using the affected application, this issue could
be leveraged to execute arbitrary code subject to the user's
privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/357438/30/0/threaded");
 script_set_attribute(
  attribute:"see_also",
  value:"http://www.securityfocus.com/archive/1/358045/30/0/threaded"
 );
 script_set_attribute(attribute:"solution", value:"Upgrade to WS_FTP Pro 9.0, as that reportedly addresses the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:ws_ftp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");

 script_require_ports(139, 445);
 exit(0);
}

# start script

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WS_FTP\WSFTP32.DLL", string:rootfile);

name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
  v = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
  set_kb_item(name:"ws_ftp_client/version", value:v);

  if ( version[0] < 9)
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "  Product           : WS_FTP Pro\n",
        "  Path              : ", rootfile, "\\WS_FTP\n",
        "  Installed version : ", v, "\n",
        "  Fix               : 9.0\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
 }
}


NetUseDel();
