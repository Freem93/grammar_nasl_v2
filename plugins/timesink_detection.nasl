#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(12003);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");


 script_name(english:"TIMESINK Spyware Detection");
 script_summary(english:"TIMESINK detection");

 script_set_attribute(attribute:"synopsis", value:"A spyware application appears to be installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the TIMESINK program. You should ensure that
:

  - the user intended to install TIMESINK (it is sometimes
    silently installed)
    - the use of TIMESINK matches your corporate mandates
    and security policies.

To remove this sort of software, you may wish to check out Ad-Aware or
Spybot.");
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/securityadvisor/pest/pest.aspx?id=453059958");
 script_set_attribute(attribute:"solution", value:"Uninstall this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencies("smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");
 script_require_ports(139, 445);
 exit(0);
}


# start the script

include("smb_func.inc");
include("audit.inc");
if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

path[0] = "software\conducent";
path[1] = "software\microsoft\windows\currentversion\uninstall\flexpak";
path[2] = "software\timesink  inc.";


port = kb_smb_transport();

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(0);
}


for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) )
       {
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_hole(kb_smb_transport());
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
