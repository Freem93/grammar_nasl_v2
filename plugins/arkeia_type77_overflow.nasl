#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17158);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2005-0491");
 script_bugtraq_id(12594);
 script_osvdb_id(14011);

 script_name(english:"Knox Arkeia Backup Client Type 77 Request Processing Buffer Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote backup service is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Arkeia Network Backup agent, used for
backups of the remote host. 

The remote version of this agent contains a buffer overflow
vulnerability that may allow an attacker to execute arbitrary commands
on the remote host with the privileges of the Arkeia daemon, usually
root." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Feb/413" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Arkeia 5.3.5, 5.2.28 our 5.1.21." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Arkeia Backup Client Type 77 Overflow (Win32)');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/18");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks the version number of the remote arkeia daemon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_require_ports(617);
 script_dependencie("arkeia_default_account.nasl");
 exit(0);
}


version =  get_kb_item("arkeia-client/617");
if ( ! version ) exit(0);
if ( ereg(pattern:"^([0-4]\.|5\.0|5\.1\.([0-9](1?[^0-9]|$)|20)|5\.2\.(1?[0-9]([^0-9]|$)|2[0-7])|5\.3\.[0-4]([^0-9]|$))", string:version))
	security_hole(617);
