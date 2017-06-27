#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25822);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-4157");
  script_bugtraq_id(25143);
  script_osvdb_id(38706);

  script_name(english:"PHP-Blogger pref.db Database Information Disclosure");
  script_summary(english:"Tries to retrieve data/pref.db");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP-Blogger, a photo blog script written in
PHP. 

The version of PHP-Blogger installed on the remote host stores
configuration information in the file 'data/pref.db' and fails to
restrict access to this file.  By issuing a direct request for the
file, an attacker can gain access to sensitive information, such as
the password hash, which can in turn allow him to gain administrative
access to the application itself." );
 script_set_attribute(attribute:"see_also", value:"http://cxsecurity.com/issue/WLB-2007080025" );
 script_set_attribute(attribute:"solution", value:
"Limit access to PHP-Blogger's 'data' directory using, say, a .htaccess
file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/28");
 script_cvs_date("$Date: 2014/01/06 23:05:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpblogger:php-blogger");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/php-blogger", "/phpblogger", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to grab the database.
  r = http_send_recv3(method:"GET", item:string(dir, "/data/pref.db"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like the exploit worked...
  if ("posts_per_page=" >< res)
  {
    report = string(
      "\n",
      "Here are the contents of the file 'data/pref.db' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      res
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}
