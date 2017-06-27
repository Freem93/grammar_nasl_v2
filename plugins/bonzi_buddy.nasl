#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11995);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");


 script_name(english:"BONZI BUDDY Software Detection");
 script_summary(english:"BONZI BUDDY detection");

 script_set_attribute(attribute:"synopsis", value:"The remote host has spyware installed on it.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the BONZI BUDDY program. You should ensure
that :

- The user intended to install BONZI BUDDY (it is sometimes
    silently
    installed)
    - The use of BONZI BUDDY matches your corporate mandates
    and security
    policies.");
  # http://web.archive.org/web/20040426030949/http://www.safersite.com/PestInfo/b/bonzibuddy.asp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc15daa2");
 script_set_attribute(attribute:"solution", value:
"Uninstall this software. To remove this sort of software, you may wish
to check out Ad-Aware or Spybot.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

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


include("smb_func.inc");
include("audit.inc");
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);

path[0] = "clsid\{a28c2a31-3ab0-4118-922f-f6b3184f5495}";
path[1] = "software\bonzi software";
path[2] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{18b79968-1a76-4953-9ebb-b651407f8998}";
path[3] = "software\microsoft\windows\currentversion\shareddlls\c:\program files\bonzibuddy\bbuddymini.exe";
path[4] = "software\microsoft\windows\currentversion\shareddlls\c:\program files\limewire\2.8.6\bonzi.url";
path[5] = "software\microsoft\windows\currentversion\shareddlls\c:\windows\system32\bonzitapfilters.dll";
path[6] = "software\microsoft\windows\currentversion\shareddlls\d:\program files\bonzibuddy\bbuddymini.exe";
path[7] = "software\microsoft\windows\currentversion\shareddlls\d:\program files\limewire\3.6.6\bonzi.url";
path[8] = "software\microsoft\windows\currentversion\shareddlls\d:\windows\system32\bonzitapfilters.dll";
path[9] = "software\microsoft\windows\currentversion\shareddlls\d:\winnt\system32\bonzitapfilters.dll";
path[10] = "software\microsoft\windows\currentversion\uninstall\bonzibuddy";



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
