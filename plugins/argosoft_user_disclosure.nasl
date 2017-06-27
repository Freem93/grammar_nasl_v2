#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16094);
 script_cve_id("CVE-2004-1428");
 script_bugtraq_id(12139);
 script_osvdb_id(11335);
 script_version("$Revision: 1.19 $");
 
 script_name(english:"ArGoSoft FTP Server USER Command Account Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft FTP Server. 

The remote version of this software returns different error messages
when a user attempts to log in using a nonexistent username or a bad
password. 

An attacker may exploit this flaw to launch a dictionary attack
against the remote host in order to obtain a list of valid user names." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?501c2e30" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft FTP 1.4.2.2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/27");
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks the error message of the remote FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1, "Cannot connect to TCP port "+port+".");

banner = ftp_recv_line(socket:soc);
if ("ArGoSoft" >!< banner )
 exit(0, "The FTP on port "+port+" is not ArGoSoft.");

send(socket:soc, data:'USER nessus' + rand() + rand() + rand() + '\r\n');
r = ftp_recv_line(socket:soc);
if ( egrep(string:r, pattern:"^530 User .* does not exist", icase:TRUE) )
	security_warning(port);
ftp_close(socket:soc);
