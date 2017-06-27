#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11635);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
 script_cve_id("CVE-2003-1572");
 script_bugtraq_id(7612);
 script_osvdb_id(2213);
 script_xref(name:"Secunia", value:"8792");

 script_name(english:"Sun Java Media Framework (JMF) Arbitrary Code Execution");
 script_summary(english:"Determines the presence of JMF");

 script_set_attribute(attribute:"synopsis", value:
"A framework installed on the remote Windows host has a code execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is using Sun Microsystems's Java Media Framework
(JMF).

There is a bug in the version installed that may allow an untrusted
applet to crash the Java Virtual Machine it is being run on, or even
to gain unauthorized privileges.

An attacker could exploit this flaw to execute arbitrary code on this
host. To exploit this flaw, the attacker would need to trick a user
into running a malicious Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jun/219");
 script_set_attribute(
   attribute:"see_also",
   value:"http://download.oracle.com/sunalerts/1000986.1.html"
 );
 script_set_attribute(attribute:"solution", value:"Upgrade to JMF 2.1.1e or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/19");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}


include("smb_func.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

port = kb_smb_transport();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Sun Microsystems, Inc.\JMF", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"LatestVersion");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

if ( isnull(item) ) exit(1);
if(ereg(pattern:"^([0-1]\.|2\.0|2\.1\.0|2\.1\.1($|[a-d]))$", string:item[1]))security_hole(port);
