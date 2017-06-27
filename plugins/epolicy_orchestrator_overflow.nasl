#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22494);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

 script_cve_id("CVE-2006-5156");
 script_bugtraq_id(20288);
 script_osvdb_id(29421);

 script_name(english:"ePolicy Orchestrator HTTP /spipe/pkg/ Source Header Remote Overflow");
 script_summary(english:"Determines the version of ePO");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
web service.");
 script_set_attribute(attribute:"description", value:
"The remote host is running McAfee ePolicy Orchestrator web service.

The remote version of this software contains a stack overflow
vulnerability.

An unauthenticated attacker can exploit this flaw by sending a
specialy crafted packet to the remote host. A successful exploitation
of this vulnerability would result in remote code execution with
SYSTEM privileges.");
 # http://web.archive.org/web/20061013072500/http://www.remote-exploit.org/advisories/mcafee-epo.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74be4c95");
 script_set_attribute(attribute:"solution", value:"Install ePO 3.5.0 Patch 6.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'McAfee ePolicy Orchestrator / ProtectionPilot Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/03");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
#if(!get_port_state(port))exit(0);

#soc = open_sock_tcp(port);

#if ( ! soc ) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Network Associates\ePolicy Orchestrator", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"InstallFolder");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);
if ( isnull(item) ) {
 NetUseDel();
 exit(0);
}

rootfile = item[1];
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile) + "\NaiMServ.Exe";

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(version) )
 {
  if ( (version[0] < 3) ||
       (version[0] == 3 && version[1] <= 5) ||
       (version[0] == 3 && version[1] == 5 && version[2] == 0 && version[3] <  715) )
 	security_hole(port);
 }
}
NetUseDel();
