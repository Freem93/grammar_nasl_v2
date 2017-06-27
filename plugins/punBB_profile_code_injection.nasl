#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17363);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-0818");
  script_bugtraq_id(12828);
  script_osvdb_id(15373);

  script_name(english:"PunBB profile.php Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PunBB installed on the remote
host fails to properly sanitize user input to the script 'profile.php'
through the 'email' and 'Jabber' parameters.  An attacker could
exploit this flaw to embed malicious script or HTML code in his
profile.  Then, whenever someone browses that profile, the code would
be executed in that person's browser in the context of the website,
enabling the attacker to conduct cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Mar/1013446.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB version 1.2.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/08");
 script_cvs_date("$Date: 2015/01/23 22:03:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Detects input validation vulnerabilities in PunBB's profile.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencie("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/punBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.(1|2$|2\.[1-3]([^0-9]|$))")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
