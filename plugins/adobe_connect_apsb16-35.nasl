#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94759);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/15 15:17:03 $");

  script_cve_id("CVE-2016-7851");
  script_bugtraq_id(94152);
  script_osvdb_id(146883);
  script_xref(name:"EDB-ID", value:"40742");
  script_xref(name:"IAVB", value:"2016-B-0161");

  script_name(english:"Adobe Connect < 9.5.7 event_registration.html Multiple Parameter XSS (APSB16-35)");
  script_summary(english:"Checks the version of Adobe Connect.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect running on the remote host is prior to
9.6.7. It is, therefore, affected by a cross-site scripting (XSS)
vulnerability in the event_registration.html script due to a failure
to properly sanitize user-supplied input to the 'firstname',
'lastname', and 'companyname' parameters. An unauthenticated, remote
attacker can exploit this issue, via a specially crafted request, to
execute arbitrary script code in a user's browser session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb16-35.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 9.5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_connect_detect.nbin");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("installed_sw/Adobe Connect");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Adobe Connect";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name: app, port: port, exit_if_unknown_ver: TRUE);

dir         = install['path'];
version     = install['display_version'];
install_url = build_url(qs:dir, port:port);

fixed_version = '9.5.7';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report =
    '\n  URL               : ' + install_url+
    '\n  Installed version : ' + version+
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
