#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15828);
 script_cve_id("CVE-2004-1128", "CVE-2004-1129", "CVE-2004-1130");
 script_bugtraq_id(11742);
 script_osvdb_id(12130, 12131, 12132, 12133);
 script_xref(name:"Secunia", value:"13298");

 script_version ("$Revision: 1.15 $");
 script_name(english:"Youngzsoft CMailServer < 5.2.1 Multiple Remote Vulnerabilities");
 script_summary(english:"Detects the version of CMail");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote mail server has multiple vulnerabilities."
 );
 script_set_attribute(attribute:"description", value:
"The remote host is running YoungZSoft CMailServer, a mail server
for Microsoft Windows.

The version of CMailServer running on the remote machine has multiple
vulnerabilities, including buffer overflow, SQL injection, and HTML
injection.  These vulnerabilities could allow a remote attacker to
execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Nov/335"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CMailServer 5.2.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/24");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/cmailserver-smtp");
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");
port = get_kb_item("Services/cmailserver-smtp");
if ( ! port ) exit(0);
banner = get_smtp_banner ( port:port);
if ( egrep(pattern:"^220 ESMTP CMailServer ([0-4]\..*|5\.([0-1]\..*|2\.0.*))SMTP Service Ready", string:banner) )
{
	security_hole ( port );
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

