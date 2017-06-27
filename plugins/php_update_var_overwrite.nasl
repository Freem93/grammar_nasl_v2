#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23927);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-6661");
  script_bugtraq_id(21658);
  script_osvdb_id(32360, 32361);
  script_xref(name:"EDB-ID", value:"2953");

  script_name(english:"PHP-Update blog.php Variable Overwriting Arbitrary Code Execution");
  script_summary(english:"Checks if variables can be overwritten with PHP-Update's blog.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a data
modification vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP-Update, a content management system
written in PHP. 

The version of PHP-Update installed on the remote host fails to
sanitize user-supplied arguments to the 'blog.php' script before
importing them into the global symbol table.  By leveraging this flaw,
an unauthenticated, remote attacker can gain control of the application
and possibly execute arbitrary code on the remote host, subject to the
permissions of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/19");
 script_cvs_date("$Date: 2012/12/13 23:12:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:php-update:php-update");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq("/phpupdate", "/phpu", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  init_cookiejar();
  erase_http_cookie(name: "blogcookie[user]");	# In case it already exists
  # If we can overwrite the variables, this request will set a cookie.
  r = http_send_recv3(method: "GET", 
    item: string(
      dir, "/blog.php?",
      "f=&",
      "newmessage=&",
      "newremember=1&",
      "adminuser=1&",
      "newusername=", SCRIPT_NAME
    ), 
    port:port
  );
  if (isnull(r)) exit(0);

  # There's a problem if we could set the user cookie.
  val = get_http_cookie(name: "blogcookie[user]");
  if (SCRIPT_NAME >< val) {
    security_hole(port);
    exit(0);
  }
}
