#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17647);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0914");
  script_bugtraq_id(12930);
  script_osvdb_id(15089, 23406, 23407);

  script_name(english:"CPG Dragonfly Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The version of CPG Dragonfly / CPG-Nuke CMS installed on the remote
host suffers from multiple cross-site scripting vulnerabilities due to
its failure to sanitize user-input to several variables in various
modules.  An attacker can exploit these flaws to steal cookie-based
authentication credentials and perform other such attacks." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Mar/1013573.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.cpgnuke.com/Forums/viewtopic/t=8940.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/29");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in CPG Dragonfly");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";


# Check various directories for CPG Dragonfly / CPG-Nuke.
foreach dir (cgi_dirs()) {
  # Try to exploit the vulnerability with our XSS.
  r = http_send_recv3(method: 'GET', item:string(dir, 
      "/index.php?",
      "name=Your%20Account&",
      "profile=anyone%22%3E" , exss
    ), port:port );
  if (isnull(r)) exit(0);

  # There's a problem if ...
  if (
    # it's from CMS Dragonfly / CPG-Nuke and...
    egrep(string:r[2], pattern:'META NAME="GENERATOR" CONTENT="CPG(-Nuke|Dragonfly)', icase:TRUE) &&
    # we see our exploit.
    (xss >< r[2])
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
