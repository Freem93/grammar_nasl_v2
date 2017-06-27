#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/2/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)

include("compat.inc");

if (description)
{
 script_id(10417);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2014/05/26 16:30:02 $");
 script_osvdb_id(319);

 script_name(english:"Sambar Server /cgi-bin/mailit.pl Arbitrary Mail Relay");
 script_summary(english:"Checks for the presence of /cgi-bin/mailit");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that allows unauthorized mail
relaying.");
 script_set_attribute(attribute:"description", value:
"The Sambar web server is running and the 'mailit.pl' cgi is installed.
This CGI takes a POST request from any host and sends a mail to a
supplied address.");
 script_set_attribute(attribute:"solution", value:"remove it from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Hendrik Scholz");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport", "www/sambar");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

cgi = "/cgi-bin/mailit.pl";
res = is_cgi_installed_ka(port:port, item:cgi);
if(res)security_warning(port);
