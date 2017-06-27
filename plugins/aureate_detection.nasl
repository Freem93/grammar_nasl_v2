#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11994);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");

 script_name(english:"AUREATE Software Detection");
 script_summary(english:"AUREATE detection");

 script_set_attribute(attribute:"synopsis", value:"The remote as an advertising program installed.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the AUREATE program. You should ensure that:
- the user intended to install AUREATE (it is sometimes silently
installed) - the use of AUREATE matches your corporate mandates and
security policies.");
 script_set_attribute(attribute:"solution", value:
"Uninstall this software if it does not match your corporate security
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}

# start the script
include("smb_func.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);


path[0] = "software\aureate";
path[1] = "clsid\{ebbfe27c-bdf0-11d2-bbe5-00609419f467}";
path[2] = "netscape starting\clsid\{ebbfe288-bdf0-11d2-bbe5-00609419f467}";
path[3] = "netscape starting\curver\stub.netscapestart.1";
path[4] = "software\classes\anadscb.aadvb5";


port = kb_smb_transport();
#if(!port || ! get_port_state(port) )exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();


#soc = open_sock_tcp(port);
#if(!soc) exit(0);

#session_init(socket:soc, hostname:kb_smb_name());
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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
	 security_note(port);
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
