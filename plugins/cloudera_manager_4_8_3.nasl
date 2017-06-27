#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76260);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/14 15:16:43 $");

  script_cve_id("CVE-2014-0220");
  script_bugtraq_id(67912);
  script_osvdb_id(107753);

  script_name(english:"Cloudera Manager < 4.8.3 / 5.x < 5.0.1 Information Disclosure");
  script_summary(english:"Checks the Cloudera Manager version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cloudera Manager running on the remote host is prior to
4.8.3 or else 5.x prior to 5.0.1. It is, therefore, affected by an
information disclosure vulnerability because the API fails to properly
restrict access to sensitive data by non-administrator users. A low
privilege user can utilize this flaw to access sensitive configuration
values that should only be accessible to users with administrative
privileges.");
  # http://www.cloudera.com/content/cloudera/en/documentation/security-bulletins/Security-Bulletin/csb_topic_2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1d4a81a");
  # http://www.cloudera.com/content/cloudera/en/documentation/cloudera-manager/v4-latest/Cloudera-Manager-Release-Notes/cmrn_fixed_in_4_8_3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73ee54a0");
  # http://www.cloudera.com/content/cloudera/en/documentation/core/latest/topics/cm_rn_fixed_issues.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72c48a32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cloudera Manager version 4.8.3 / 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudera:cloudera_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cloudera_manager_detect.nbin");
  script_require_keys("installed_sw/Cloudera Manager");
  script_require_ports("Services/www", 7180, 7183);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cloudera Manager";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:7183);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];
install_url = build_url(port:port, qs:dir);

vuln = FALSE;

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 4)
{
  fix = "4.8.3 / 5.0.1";
  vuln = TRUE;
}
else if (version =~ "^4\.")
{
  if (
    (ver[0] == 4 && ver[1] < 8) ||
    (ver[0] == 4 && ver[1] == 8 && ver[2] < 3)
  )
  {
    fix = "4.8.3";
    vuln = TRUE;
  }
}
else if (version =~ "^5\.0\.0($|[^0-9]+)")
{
  fix = "5.0.1";
  vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
