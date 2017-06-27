#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31606);
  script_version("$Revision: 1.13 $");

  script_bugtraq_id(28275);
  script_osvdb_id(50426);
  script_xref(name:"EDB-ID", value:"5267");

  script_name(english:"XOOPS Dictionary Module print.php id Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a definition");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of the Dictionary module for XOOPS installed on the remote
host fails to sanitize user-supplied input to the 'id' parameter of
the 'print.php' script before using it in a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an attacker may be
able to exploit this issue to manipulate database queries, leading to
disclosure of sensitive information, execution of arbitrary code, or
attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/19");
 script_cvs_date("$Date: 2013/01/03 22:39:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:xoops:xoops_dictionary");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to manipulate a definition.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("-99999 UNION SELECT ", magic1, ",", magic2, "--");

  r = http_send_recv3(method: "GET", port: port, 
    item:string(
      dir, "/modules/dictionary/print.php?", 
      "id=", str_replace(find:" ", replace:"/**/", string:exploit)
    ));
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if we could manipulate a definition.
  if (
    string(">Term: </b> ", magic1, "<P>") >< res &&
    string(">Definition: </b> ", magic2) >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
