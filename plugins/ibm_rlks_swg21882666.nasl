#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83520);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/19 23:59:42 $");

  script_cve_id("CVE-2015-1907");
  script_bugtraq_id(74552);
  script_osvdb_id(121373);

  script_name(english:"IBM Rational License Key Server Administration and Reporting Tool 8.1.4.x < 8.1.4.7 XSS");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Rational License Key
Server Administration and Reporting Tool (RLKS) that is 8.1.4.x prior
to 8.1.4.7. It is, therefore, affected by a cross-site scripting
vulnerability that allows an attacker to steal cookies and impersonate
a valid user.");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21882666");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rational License Key Server Fix Pack 7 (8.1.4.7) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_license_key_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_rlks_administration_reporting_tool.nbin");
  script_require_keys("installed_sw/IBM Rational License Key Server Administration and Reporting Tool");
  script_require_ports("Services/www", 4743);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:4743);

app = "IBM Rational License Key Server Administration and Reporting Tool";

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];
install_url = build_url(port:port, qs:path);

fix = "8.1.4.7";
if (
  version =~ "^8\.1\.4$" ||
  (version =~ "^8\.1\.4\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             '\n  Install path      : ' + install_url + 
             '\n';

    security_note(port:port, extra:report);
  }
  else security_note(port:port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
