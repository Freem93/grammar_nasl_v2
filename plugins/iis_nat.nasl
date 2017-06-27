#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Enhanced description (10/28/09)


include("compat.inc");

if(description)
{
 script_id(10759);
 script_version ("$Revision: 1.55 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");

 script_cve_id("CVE-2000-0649");
 script_bugtraq_id(1499);
 script_osvdb_id(630);

 script_name(english:"Web Server HTTP Header Internal IP Disclosure");
 script_summary(english:"Checks for private IP addresses in HTTP headers");

 script_set_attribute(attribute:"synopsis", value:
"This web server leaks a private IP address through its HTTP headers." );
 script_set_attribute(attribute:"description", value:
"This may expose internal IP addresses that are usually hidden or
masked behind a Network Address Translation (NAT) Firewall or proxy
server. 

There is a known issue with Microsoft IIS 4.0 doing this in its default
configuration. This may also affect other web servers, web applications,
web proxies, load balancers and through a variety of misconfigurations
related to redirection." );
 # https://web.archive.org/web/20000819132257/http://archives.neohapsis.com/archives/ntbugtraq/2000-q3/0025.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe24f941");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;EN-US;Q218180");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;EN-US;834141");
 script_set_attribute(attribute:"solution", value:"None");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/09/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Alert4Web.com, 2003 Westpoint Ltd");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("misc_func.inc");

if ( report_paranoia == 0 )
{
 if ( ! all_addr_public )  exit(0);
}
else if ( all_addr_private ) exit(0);


dirs = get_kb_list(string("www/", port, "/content/directories"));
if ( isnull(dirs) ) dirs = make_list("/");
else dirs = make_list(dirs);

port = get_http_port(default:80);

# It sometimes works with an non existing URI
items_l = make_list(dirs[0], strcat(dirs[0], "/", rand_str(), ".asp"));

foreach item (items_l)
{
#
# Craft our own HTTP/1.0 request for the server banner.
# Note: HTTP/1.1 is rarely useful for detecting this flaw.
#
soc = open_sock_tcp(port);
if(!soc) exit(0);
send(socket:soc, data:string("GET ", item, " HTTP/1.0\r\n\r\n"));
banner = http_recv_headers2(socket:soc);
http_close_socket(soc);

#
# Check for private IP addresses in the banner
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
#
private_ip = eregmatch(pattern:"[^0-9]0*(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})($|[^0-9.])", string:banner);
if(
  !isnull(private_ip) && 
  ! egrep(pattern:"(^X-ORCL-.+: *|Oracle.*)10\.", string:banner) && 
  (private_ip[1] != get_host_ip())
)
{
 if (report_verbosity > 0)
 {
  report = string(
   "\n",
   "When processing the following request :\n",
   "\n",
   "  GET ", item, " HTTP/1.0\n",
   "\n",
   "this web server leaks the following private IP address :\n",
   "\n",
   "  ", private_ip[1], "\n",
   "\n",
   "as found in the following collection of HTTP headers :\n",
   "\n",
   banner
  );
  security_note(port:port, extra:report);
 }
 else security_note(port);
 exit(0);
}
}
