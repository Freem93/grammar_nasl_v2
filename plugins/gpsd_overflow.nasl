#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16265);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1388");
 script_bugtraq_id(12371);
 script_osvdb_id(13199);

 script_name(english:"Berlios gpsd gpsd_report() Function Format String");
 script_summary(english:"Checks the version of the remote gpsd server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a GPS monitoring application that is
vulnerable to a format string attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GPSD, a daemon which monitors a GPS device
and publishes its data over the network.

The remote version of this software is vulnerable to format string attack
due to the way it uses the syslog() call. An attacker may exploit this flaw
to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jan/812" );
 # "http://www.mail-archive.com/debian-bugs-closed@lists.debian.org/msg02103.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37576239" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to gpsd 2.8 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Berlios GPSD Format String Vulnerability');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/27");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/01/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/26");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/gpsd", 2947);
 exit(0);
}


port = get_kb_item("Services/gpsd");
if ( ! port ) port = 2947;

if ( ! get_port_state( port ) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'HELP\r\n');
r = recv_line(socket:soc, length:4096);
if ( ! r || "GPSD," >!< r ) exit(0);

version = ereg_replace(pattern:".*GPSD,.* ([0-9.]+) .*", string:r, replace:"\1");
if ( version == r ) exit(0);

if ( ereg(pattern:"^([01]|2\.[0-7]$)", string:version) )
	security_hole(port);
