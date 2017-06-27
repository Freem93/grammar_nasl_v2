#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");
if(description)
{
 script_id(15628);
 script_cve_id("CVE-2004-1626", "CVE-2004-1627");
 script_bugtraq_id(11508);
 script_osvdb_id(11030, 12347);
 script_xref(name:"Secunia", value:"12941");

 script_version("$Revision: 1.15 $");
 
 script_name(english:"Ability FTP Server Multiple Command Remote Buffer Overflows");
 script_summary(english:"Gets the version of the remote Ability FTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to multiple remote buffer
overflow attacks. ");

 script_set_attribute(attribute:"description", value:
"The remote host is running Ability FTP Server. It is reported
that the remote version of this software is prone to a remote buffer
overflow attack via the 'STOR' and 'APPE' commands. An attacker,
exploiting this flaw, would only need to be able to craft and send a
query to the FTP server on its service port (usually 21).");

 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2004/Oct/252");
 # http://web.archive.org/web/20060921101554/http://lists.virus.org/dw-0day-0412/msg00004.html
 script_set_attribute(attribute:"see_also", value:
"http://www.nessus.org/u?cbaf8896");
 
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ability FTP Server version 2.35 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Ability Server 2.34 STOR Command Stack Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/22");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("ftp_func.inc");


port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1, "Cannot read FTP banner on port "+port+".");

if ( egrep(pattern:"^220 Welcome to Code-Crafters - Ability Server ([0-1]\..*|2\.([0-2]|3[0-4]))[^0-9]", string:banner) ) security_hole(port);

