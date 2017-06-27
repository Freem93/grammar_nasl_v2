#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78066);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/06 19:02:17 $");

  script_cve_id("CVE-2014-3092");
  script_bugtraq_id(69775);
  script_osvdb_id(111225);

  script_name(english:"IBM Jazz Team Server Session Cookie Information Disclosure");
  script_summary(english:"Checks for an insecure session cookie.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is utilizing an insecure session cookie.");
  script_set_attribute(attribute:"description", value:
"The remote IBM Jazz Team server is using a session cookie without the
'Secure' flag. A failure to set this flag may allow an attacker to
intercept the cookie.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21682787");
  script_set_attribute(attribute:"solution", value:"Upgrade to the recommended version according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:jazz_team_server");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_jazz_team_server_detect.nbin");
  script_require_keys("installed_sw/IBM Jazz Team Server");
  script_require_ports("Services/www", 9443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "IBM Jazz Team Server";

port = get_http_port(default:9443);

install = get_single_install(app_name:app, port:port);

dir = install['path'];

res = http_send_recv3(port:port,
                      method:'GET',
                      item:dir,
                      follow_redirect:3,
                      exit_on_fail:TRUE);

lines = split(res[1]);

vuln = FALSE;

foreach line (lines)
{
  report_cookie = line;
  line = tolower(line);
  if (
    'set-cookie' >< line && 
    'expires' >!< line && 
    'secure' >!< line && 
    'formauth' >< line
  )
  {
    vuln = TRUE;
    break;
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'Nessus detected the following insecure session cookie on the remote host : ' +
      '\n' + 
      '\n' + report_cookie + 
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, port);
