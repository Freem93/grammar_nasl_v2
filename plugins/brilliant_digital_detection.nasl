#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11996);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/10/03 20:24:52 $");

 script_name(english:"Brilliant Digital Software Detection");
 script_summary(english:"Brilliant Digital detection");

 script_set_attribute(attribute:"synopsis", value:
"Spyware is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"Brilliant Digital, a media player that tracks browsing habits, is
installed on the remote host. This program has been reported to cause
excessive CPU and memory consumption and occasional crashes.");
  # http://web.archive.org/web/20031028164929/http://www.safersite.com/PestInfo/b/brilliantdigital.asp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64866ea4");
 script_set_attribute(attribute:"solution", value:
"Ensure Brilliant Digital was intended to be installed (it is sometimes
silently installed), and that the use of this software is in
accordance with your corporate mandates and security policies. If not,
then remove the software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}

# start the script
include("smb_func.inc");
include("audit.inc");
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);

path[0] = "software\altnet";
path[1] = "software\brilliant digital entertainment";
path[2] = "software\microsoft\code store database\distribution units\{8721f16d-cbf8-4ce5-b924-18d64e12e77e}";
path[3] = "software\microsoft\windows\currentversion\uninstall\bdeplayer";
path[4] = "software\microsoft\windows\currentversion\uninstall\{e37135e3-cc51-4d5d-96a6-7116fc4058d4}";

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
	 security_warning(kb_smb_transport());
	 NetUseDel();
	 exit(0);
       }
}

RegCloseKey(handle:handle);
NetUseDel();
