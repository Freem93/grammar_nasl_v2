#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10609);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2001-0224");
 script_bugtraq_id(2374);
 script_osvdb_id(505);

 script_name(english:"Muscat Empower CGI Malformed DB Parameter Path Disclosure");
 script_summary(english:"Attempts to find the location of the remote web root");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description",  value:
"The remote host appears to be running Muscat Empower.  It was possible
to get the physical location of a virtual web directory by issuing the
following command :

  GET /cgi-bin/empower?DB=whatever HTTP/1.0

A remote attacker could use this information to mount further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2001/Feb/53"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/12");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
  d = string(dir, "/empower?DB=whateverwhatever");
  r = http_send_recv3(method:"GET", item:d, port:port);
  if (isnull(r)) exit(0);

  r[2] = tolower(r[2]);
  if("db name whateverwhatever of directory /" >< r[2]){
  	security_warning(port);
	exit(0);
	}
}
