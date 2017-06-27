#
# This script was written by Erik Tayler <erik@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)


include("compat.inc");

if(description)
{
	script_id(11207);
	script_version("$Revision: 1.17 $");

	script_cve_id("CVE-1999-0256");
	script_bugtraq_id(10078);
	script_osvdb_id(875);
	
	script_name(english:"WarFTPd USER/PASS Command Remote Overflow");
	script_summary(english:"War FTP Daemon USER/PASS Overflow");

	script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote FTP server." );
	script_set_attribute(attribute:"description", value:
"The version of War FTP Daemon running on this host contains a buffer
overflow in the code that handles the USER and PASS commands.  A
potential intruder could use this vulnerability to crash the server,
as well as run arbitrary commands on the system." );
	script_set_attribute(attribute:"solution", value:
"Upgrade to WarFTPd version 1.66x4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'War-FTPD 1.65 Username Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value:
"2003/01/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/03/19");
 script_cvs_date("$Date: 2015/05/22 14:14:42 $");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003-2015 Digital Defense, Inc.");
	script_family(english:"FTP");
	script_dependencies("ftpserver_detect_type_nd_version.nasl");
	script_require_ports("Services/ftp", 21);
	exit(0);
}


include("ftp_func.inc");

port = get_ftp_port(default: 21);

r = get_ftp_banner(port:port);
if (!r) exit(1);

	if(egrep(pattern:"WAR-FTPD 1.([0-5][0-9]|6[0-5])[^0-9]*Ready",string:r, icase:TRUE))
	{
		security_hole(port);
	}

