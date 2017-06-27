#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18541);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2028");
  script_bugtraq_id(14015);
  script_osvdb_id(17406);

  script_name(english:"MercuryBoard User-Agent SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MercuryBoard, an open source bulletin board
system that uses PHP and MySQL. 

The installed version of MercuryBoard fails to remove malicious data
from a User-Agent header before using it in a database query, making
it prone to SQL injection attacks.  An authenticated attacker can
exploit this flaw to modify database updates, possibly modifying data
and launching attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/402929/30/0/" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/21");
 script_cvs_date("$Date: 2013/01/18 22:59:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:mercuryboard:mercuryboard_message_board");
script_end_attributes();

  script_summary(english:"Checks for User-Agent remote SQL injection vulnerability in MercuryBoard");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw.
  w = http_send_recv3(method:"GET", port: port, item: dir+"/index.php",
    add_headers: make_array("User-Agent", SCRIPT_NAME+"'"));
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];
  # There's a problem if...
  if (
    # It looks like MercuryBoard and...
    "<title>MercuryBoard Error</title>" >< res && 
    # We see a syntax error with our script name.
    egrep(string:res, pattern:string("Query.+REPLACE INTO.+'", SCRIPT_NAME, "''"))
  ) { 
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
