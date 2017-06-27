#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(17163);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");
 script_cve_id("CVE-2005-0441");
 script_bugtraq_id(13020, 13015, 13014, 13013, 13012, 13009, 12562);
 script_osvdb_id(15198, 15199, 15326, 15327, 15328);

 script_name(english:"Sybase Adaptive Server Enterprise < 12.5.4.0 Multiple Vulnerabilities");
 script_summary(english:"Checks the version of the remote Sybase server");

 script_set_attribute(attribute:"synopsis", value:
"The remote database service is affected by unspecified
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Sybase Adaptive Server Enterprise, a SQL
server with network capabilities.

The remote version of this software is earlier than 12.5.4.0. Such
versions are affected by several unspecified security flaws.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/385198");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 12.5.4.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/21");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencies("sybase_blank_password.nasl", "smb_hotfixes.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");

#
# The script code starts here
#


version = get_kb_item("sybase/version");
if ( ! version )
{
 if ( ! get_kb_item("SMB/full_registry_access") ) exit(0);

 port = get_kb_item("SMB/transport");
 if(!port)port = 139;

 name	= kb_smb_name(); 	if(!name)exit(0);
 login	= kb_smb_login();
 pass	= kb_smb_password();
 domain  = kb_smb_domain();
 port	= kb_smb_transport();



 if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
 r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
 if ( r != 1 ) exit(0);

 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if ( isnull(hklm) )
 {
  NetUseDel();
  exit(0);
 }


 key = "SOFTWARE\SYBASE\SQLServer";
 item = "CurrentVersion";

 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  value = RegQueryValue(handle:key_h, item:item);

  if (!isnull (value))
    version = value[1];

  RegCloseKey (handle:key_h);
 }


 RegCloseKey (handle:hklm);
 NetUseDel ();
}

if ( version && ereg(pattern:"([0-9]\.|11\.|12\.[0-4]\.|12\.5\.[0-3]\.)", string:version) )
	security_hole(get_kb_item("Services/sybase"));
