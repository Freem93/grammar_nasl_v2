#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(14307);
  script_version ("$Revision: 1.21 $"); 

  script_bugtraq_id(10666);
  script_osvdb_id(7958);

  name["english"] = "BasiliX Webmail Content-Type Header XSS";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running BasiliX version 1.1.1 or lower. 
Such versions are vulnerable to a cross-scripting attack whereby an
attacker may be able to cause a victim to unknowingly run arbitrary
JavaScript code in his browser simply by reading a MIME message with a
specially crafted Content-Type header." );
 script_set_attribute(attribute:"see_also", value:"http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BasiliX version 1.1.1 fix1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/05");
 script_cvs_date("$Date: 2015/01/13 06:57:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for Content-Type XSS vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_dependencie("basilix_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/basilix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.0.*|1\.1\.(0|1))$") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
