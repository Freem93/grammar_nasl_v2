#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25117);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-2079");
  script_bugtraq_id(23491);
  script_osvdb_id(41594);

  script_name(english:"XAMPP ADOdb mssql_connect Remote Buffer Overflow");
  script_summary(english:"Tries to generate an error with mssql_connect");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running XAMPP, an Apache distribution containing
MySQL, PHP, and Perl.  It is designed for easy installation and
administration. 

The remote version of XAMPP includes a PHP interpreter that is
affected by a buffer overflow involving calls to 'mssql_connect()' as
well as an example PHP script that allows this function to be called
with arbitrary arguments.  Using a specially crafted value for the
'host' parameter of the 'xampp/adodb.php' script, an unauthenticated,
remote attacker can leverage these issues to execute arbitrary code on
the affected host subject to the privileges under which the web server
operates, potentially LOCAL SYSTEM." );
 script_set_attribute(attribute:"see_also", value:"http://packetstorm.linuxsecurity.com/0704-exploits/xampp-rgod.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.apachefriends.org/en/news-article,100366.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.apachefriends.org/en/xampp-windows.html#1221" );
 script_set_attribute(attribute:"solution", value:
"Use XAMPP's Security Console to restrict access to the '/xampp'
directory." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-409");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/30");
 script_cvs_date("$Date: 2016/05/04 18:02:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Make sure the affected script exists.
url = "/xampp/adodb.php";
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);
res = r[2];

# If it does...
if (
  'name="dbserver"' >< res &&
  '<meta name="author" content="Kai Oswald Seidler' >< res
)
{
  # Unless we're being paranoid, just flag the flaw.
  if (report_paranoia < 2)
  {
    security_hole(port);
    exit(0);
  }

  # See if we have control over parameters to mssql_connect().
  postdata = string(
    "dbserver=mssql&",
    "host=", crap(500), "&",
    "adodb=submit&",
    "user=1&",
    "password=1&",
    "database=nessus&",
    "table=", SCRIPT_NAME
  );
  r = http_send_recv3(method: "POST", item: url, version: 11, port: port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), 
    data: postdata);
  if (isnull(r)) exit(0);
  res = r[2];

  # If so...
  if (string('mssql error: [: ] in EXECUTE("SELECT * FROM ', SCRIPT_NAME, '")') >< res)
  {
    security_hole(port);
    exit(0);
  }
}
