#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21215);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-1718");
  script_bugtraq_id(17461);
  script_osvdb_id(24495);

  script_name(english:"Clever Copy connect.inc Direct Request Information Disclosure");
  script_summary(english:"Reads Clever Copy's admin/connect.inc file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Clever Copy, a free web portal written in
PHP. 

The version of Clever Copy installed on the remote host fails to limit
access to the 'admin/connect.inc' include file, which contains
information used by the application to connect to a database.  An
unauthenticated attacker can view the contents of this file using a
simple GET command and use the information to launch other attacks
against the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c952ae9c" );
 script_set_attribute(attribute:"solution", value:
"Limit access to Clever Copy's admin directory using, say, a .htaccess
file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/07");
 script_cvs_date("$Date: 2015/09/24 21:08:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to read the file.
  r = http_send_recv3(method:"GET", item:string(dir, "/admin/connect.inc"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if it looks like the file.
  if (egrep(pattern:"\$(Host|Dbase|User|Pass)[ \t]*=[ \t]*", string:res))
  {
    report = string(
      "\n",
      "Here are the contents of the file 'admin/connect.inc' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      res
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
