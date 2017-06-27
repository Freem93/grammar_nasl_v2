#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20179);
  script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2005-3483");
  script_bugtraq_id(15285);
  script_osvdb_id(20464);

  script_name(english:"GO-Global for Windows _USERSA_ Remote Overflow (credentialed check)");
  script_summary(english:"Checks for buffer overflow vulnerability in GO-Global");

 script_set_attribute(attribute:"synopsis", value:
"The remote display client or server is affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to the Windows registry, the remote host is running a
version of the GO-Global remote display client or server that fills a
small buffer with user-supplied data without first checking its size.
An attacker can leverage this issue to overflow the buffer, causing
the server to crash and possibly even allowing for arbitrary code
execution on the remote host.");
  # http://lists.grok.org.uk/pipermail/full-disclosure/2005-November/038371.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77a07053");
 script_set_attribute(attribute:"solution", value:"Upgrade to GO-Global version 3.1.0.3281 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/10");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"x-cpe:/a:graphon:go-global");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

#if(!get_port_state(port))exit(1);
#soc = open_sock_tcp(port);
#if(!soc)exit(1);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\GraphOn\Bridges", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"RootPath");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(0);
}


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value[1]);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Programs\cs.dll", string:value[1]);
NetUseDel(close:FALSE);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) {
 NetUseDel();
 exit(1);
}



handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if (!isnull(v))
 if ( ( v[0] < 3 ) ||
      ( ( v[0] == 3 ) && ( v[1] < 1 ) ) ||
      ( ( v[0] == 3 ) && ( v[1] == 1 ) && ( v[2] == 0 ) && ( v[3] < 3281 ) ) )
    security_hole(port);
}

NetUseDel();
