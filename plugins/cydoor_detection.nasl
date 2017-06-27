#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");


if (description)
{
 script_id(12012);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

 script_name(english:"CYDOOR Software Detection");
 script_summary(english:"CYDOOR detection");

 script_set_attribute(attribute:"synopsis", value:"An adware program is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"Cydoor Desktop Media, an adware program, is installed on the remote
host. This program displays pop-up/pop-under advertisements and
changes web browser settings (e.g., homepage) without the user's
permission.");
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/securityadvisor/pest/pest.aspx?id=1472");
 script_set_attribute(attribute:"solution", value:"Remove this program using an adware or spyware removal product.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# start the script

include("smb_func.inc");
include("audit.inc");
if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

path[0] = "software\cydoor";
path[1] = "software\microsoft\windows\currentversion\uninstall\adsupport_336";
path[2] = "software\microsoft\windows\currentversion\uninstall\adsupport_202";
path[3] = "software\microsoft\windows\currentversion\uninstall\adsupport_253";
path[4] = "software\microsoft\windows\currentversion\uninstall\adsupport_270";
path[5] = "software\microsoft\windows\currentversion\uninstall\adsupport_277";
path[6] = "software\microsoft\windows\currentversion\uninstall\adsupport_314";
path[7] = "software\microsoft\windows\currentversion\uninstall\adsupport_319";


port = kb_smb_transport();

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(1);
}


for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) )
       {
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_warning(kb_smb_transport());
	 NetUseDel();
	 exit(1);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
