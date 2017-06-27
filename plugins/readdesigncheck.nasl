#
# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
# By: Hemil Shah
# Desc: This script will check for the ReadDesign vuln on names.nsf.

# Changes by Tenable:
# - Changed output check to reduce FPs
# - Updated see_also reference
# - Revised plugin title, enhanced description, added OSVDB ref (7/06/09)
# - Solution workaround added (7/06/09)
#   http://www-10.lotus.com/ldd/nd6forum.nsf/ReleaseAllThreadedweb/88a8f6e9230eda8285257501004f7d18?OpenDocument
# - Standardize title (9/18/09)


include("compat.inc");

if(description)
{
	script_id(12249);
	script_version ("$Revision: 1.15 $");
	script_osvdb_id(55663);
	script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 	script_name(english:"IBM Lotus Domino ?ReadDesign Request Design Element Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server allows an attacker to view an XML list of design
elements by sending a specially crafted HTTP request to the remote
Lotus Domino server:

http://[target]/names.nsf/view?ReadDesign" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76aceeb8");
 script_set_attribute(attribute:"solution", value:
"As a workaround, an administrator can create a server redirection
document that will redirect incoming URLs with 'ReadDesign' to
a custom error page (e.g., /CustomError)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 	script_summary(english:"ReadDesign checker");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2004-2013 Net-Square Solutions Pvt Ltd.");
	script_family(english:"Web Servers");
	script_dependencie("webmirror.nasl", "http_version.nasl");
	script_require_ports("Services/www", 80);
	exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if ( get_kb_item("www/no404/" + port) ) exit(0);


nsf =  get_kb_list(string("www/", port, "/content/extensions/nsf"));
if ( ! isnull(nsf) ) {
	nsf = make_list(nsf);
	file = nsf[0];
	}
else
	file = "/names.nsf";

req = string(file, "/view?ReadDesign");
http = http_get(item:req, port:port);
res = http_keepalive_send_recv(port:port, data:http, fetch404:TRUE);
if ( res == NULL ) exit(0);

if (
  egrep(pattern:"HTTP Web Server: .* - view", string:res) &&
  'Couldn\'t find design note' >!< res
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The following request triggered the vulnerability :\n",
      "\n",
      "  ", build_url(port:port, qs:req), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The host is not affected on port '+port+'.');
