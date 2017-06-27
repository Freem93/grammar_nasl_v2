#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24864);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-1259");
  script_bugtraq_id(22691);
  script_osvdb_id(33272);

  script_name(english:"Webapp.org WebAPP < 0.9.9.6 Multiple Vulnerabilities");
  script_summary(english:"Checks for an XSS flaw in WebAPP");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of WebAPP from webapp.org installed on the remote host is
affected by multiple, as-yet unspecified issues that could be abused
by a remote attacker to completely compromise the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85d8b8c8" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?002d99e2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to webapp.org WebAPP version 0.9.9.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/22");

 script_cvs_date("$Date: 2015/02/13 21:07:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("webapp_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


xss = string("'';!--", '"', "<BODY ONLOAD=alert('", SCRIPT_NAME, "')>=&{()}");


# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Send a request to exploit an XSS flaw.
  referer = string("://", get_host_name(), dir, "/index.cgi");
  if (get_port_transport(port) > ENCAPS_IP) referer = "https" + referer;
  else referer = "http" + referer;

  url = string(dir, "/index.cgi?action=search");
  postdata = string("pattern=", urlencode(str:xss));
  r = http_send_recv3(method:"POST", item: url, port: port, data: postdata,
    add_headers: make_array( "Referer", referer, 
    		 	     "Content-Type", "application/x-www-form-urlencoded"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if our exploit as the language.
  xss = str_replace(find:'"', replace:"&quot;", string:xss);
  if (string('No matches found for <b>"', xss, '"</b>') >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
