#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15938);
 script_version("$Revision: 1.11 $"); 

 script_bugtraq_id(11841);
 script_osvdb_id(7974);

 script_name(english:"PunBB Search Dropdown Private Forum Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of PunBB reportedly may
include protected forums in a search dropdown list regardless of
whether a user has permissions to view those forums." );
 script_set_attribute(attribute:"see_also", value:"http://www.punbb.org/changelogs/1.1.4_to_1.1.5.txt" );
 script_set_attribute(attribute:"solution", value:
"Update to PunBB version 1.1.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/03");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for PunBB version for information disclosure");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses");
 script_dependencie("punBB_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/punBB");
 exit(0);
}

#
# The script code starts here
#

include('http_func.inc');

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.[1-4]([^0-9]|$))",string:ver))
  {
    security_warning(port);
    exit(0);
  }
}
