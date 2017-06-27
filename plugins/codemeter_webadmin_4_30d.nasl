#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57800);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/23 16:10:43 $");

  script_bugtraq_id(49437);
  script_osvdb_id(76407);

  script_name(english:"CodeMeter Virtual Directory Traversal Arbitrary File Access");
  script_summary(english:"Checks the CodeMeter WebAdmin version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a directory
traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the CodeMeter WebAdmin server
installed on the remote host is prior to 4.30d (4.30.498.504). It is,
therefore, affected by a directory traversal vulnerability due to a
failure to properly sanitize HTTP requests for files in virtual
directories. An unauthenticated, remote attacker can exploit this
issue to retrieve the contents of arbitrary files on the remote host,
provided the target file is among a list of allowed extensions (for
example, 'txt', 'htm', 'html', 'images', etc.).");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/codemeter_1-adv.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to CodeMeter 4.30d (4.30.498.504) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wibu:codemeter_runtime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("codemeter_webadmin_detect.nasl");
  script_require_keys("installed_sw/CodeMeter");
  script_require_ports("Services/www", 22350);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "CodeMeter";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:22350, embedded:TRUE);

install = get_single_install(
  app_name:app,
  port:port,
  exit_if_unknown_ver:TRUE
);

dir = install['path'];
install_url = build_url(port:port,qs:dir);

version = install['version'];
disp_ver = install['display_version'];

fixed_version = "4.30.498.504";
fixed_version_ui = "4.30d (4.30.498.504)";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + disp_ver +
      '\n  Fixed version     : ' + fixed_version_ui +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, disp_ver);
