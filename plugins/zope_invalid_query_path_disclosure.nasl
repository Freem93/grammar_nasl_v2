#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11769);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2011/07/19 11:11:27 $");

 script_bugtraq_id(7999);
 script_osvdb_id(58284);
 
 script_name(english:"Zope Invalid Query Path Disclosure");
 script_summary(english:"Checks for Zope Examples directory");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that is prone to
an information disclosure attack.");
 script_set_attribute(attribute:"description", value:
"The remote Zope web server may be forced into disclosing its physical
path when calling 'Examples/ShoppingCart/addItems' with a blank
quantity. 

Note that this install is also likely to be affected by several other
vulnerabilities, although Nessus has not checked for them.");
 # http://web.archive.org/web/20081121041101/http://exploitlabs.com/files/advisories/EXPL-A-2003-009-zope.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b6ae986");
 script_set_attribute(attribute:"solution", value:
"Delete the directory '/Examples'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/23");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/zope");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);	# We should also try 8080

# nb: this is Example-3 from Exploitlabs' advisory.
u = "/Examples/ShoppingCart/addItems?orders.id%3Arecords=510-007&orders.quantity%3Arecords=&orders.id%3Arecords=510-122&orders.quantity%3Arecords=0&orders.id%3Arecords=510-115&orders.quantity%3Arecords=0";

r = http_send_recv3(method: "GET", port:port, item: u, exit_on_fail:TRUE);
a = r[2];

if("invalid literal for int()" >< a && "Publish.py"  >< a)
{
  security_warning(port);
  }
