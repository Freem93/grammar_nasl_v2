#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34304);
  script_version("$Revision: 1.7 $");
script_cvs_date("$Date: 2012/02/22 12:10:11 $");
  script_osvdb_id(50374);

  script_xref(name:"EDB-ID", value:"6492");

  script_name(english:"Pluck update.php Remote Privilege Escalation");
  script_summary(english:"Tests if update.php is accessible");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that should not be
accessible." );
 script_set_attribute(attribute:"description", value:
"The remote host is running pluck, a simple content management system
written in PHP. 

The installation of pluck on the remote host allows an anonymous
remote attacker to call the 'update.php' script, which is intended
only for upgrading from one version of pluck to another. 

Note that an attacker may be able to use this script to disable the
affected application and possibly even execute arbitrary PHP code,
although Nessus has not checked for this." );
 script_set_attribute(attribute:"solution", value:
"Remove the 'update.php' script." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/pluck", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/update.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If the script is available...
  if ("<p>Welcome to the pluck upgrading script" >< res)
  {
    # Make sure the installer has been run.
    url2 = string(dir, "/install.php");

    r2 = http_send_recv3(method:"GET", item:url2, port:port);
    if (isnull(r2)) exit(0);
    res2 = r2[2];

    res2 = chomp(res2);
    if ("pluck has already been installed" >< res2) 
      security_warning(port);
  }
}
