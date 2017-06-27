#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11751);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/05/25 23:45:39 $");
 script_bugtraq_id(7945);
 script_osvdb_id(4324);

 script_name(english:"Dune Web Server GET Request Remote Overflow");
 script_summary(english:"Checks for Dune Overflow");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Dune Web server that is
older than 0.6.8.

There is a flaw in this software that could be exploited by an
attacker to gain a shell on this host.");
 script_set_attribute(attribute:"solution", value:"Use another web server or upgrade to Dune 0.6.8");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);


if( safe_checks() )
{
 banner = get_http_banner(port:port);
 if( banner == NULL ) exit(0);

 if(egrep(pattern:"^Server: Dune/0\.([0-5]\.|6\.[0-7]$)", string:banner))
  {
   security_hole(port);
  }
  exit(0);
}


banner = get_http_banner(port:port);
if(!banner)exit(0);
if("Dune/" >!< banner)exit(0);

if(http_is_dead(port:port))exit(0);

r = http_send_recv3(method: "GET", item:"/" + crap(51), port:port);
if(! isnull(r))
{
 r = http_send_recv3(method: "GET", item:"/~" + crap(50), port:port);
 if (isnull(r)) security_hole(port);
}
