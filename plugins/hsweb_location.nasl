#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/04/01. Webmirror3.nbin will identify browsable
# directories.

include("compat.inc");

if(description)
{
 script_id(10606);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/12/30 22:07:39 $");

 script_cve_id("CVE-2001-0200");
 script_bugtraq_id(2336);
 script_osvdb_id(502);

 script_name(english:"HSWeb HTTP Server /cgi Directory Request Path Disclosure (deprecated)");
 script_summary(english:"Retrieve the real path using /cgi.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"It is possible to request the physical location of the remote web root
by requesting the folder '/cgi'. An attacker can exploit this flaw to
gain more knowledge about this host.

This plugin has been deprecated. Webmirror3 (plugin ID 10662) will
identify a browsable directory.");
 # https://web.archive.org/web/20081006092607/http://archives.neohapsis.com/archives/bugtraq/2001-02/0052.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?727554c9" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/04");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Webmirror3 (plugin ID 10662) will identify a browsable directory.");

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/cgi", port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if("Directory listing of" >< res[2])
{
  security_warning(port:port);
  exit(0);
}

