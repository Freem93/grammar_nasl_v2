#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77115);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_bugtraq_id(66707);
  script_osvdb_id(
    105583,
    105584,
    105585,
    105586,
    105587,
    105588,
    105589,
    105590
  );
  script_xref(name:"EDB-ID", value:"32743");

  script_name(english:"Halon Security Router < 3.2r2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Halon SR.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Halon Security
Router running on the remote host is affected by multiple
vulnerabilities :

  - Multiple reflected cross-site scripting vulnerabilities
    exist in the web interface due to a failure to sanitize
    user-supplied input.

  - Multiple cross-site request forgery vulnerabilities
    exist in the web interface due to a lack of XSRF tokens
    in forms.

  - Multiple open redirect vulnerabilities exist in the web
    interface due to a failure to sanitize the user-supplied
    'uri' parameter in multiple locations.");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.2r2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:halon:security_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("halon_sr_detect.nbin");
  script_require_keys("installed_sw/Halon Security Router");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "Halon Security Router";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:443);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];
display_version = install['display_version'];
url = install['path'];
report_url = build_url(port:port, qs:url);

fix = "3.2.2";
display_fix = "3.2r2";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:"www/" + port + '/XSRF', value:TRUE);
  set_kb_item(name:"www/" + port + '/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL           : ' + report_url +
      '\n  Version       : ' + display_version +
      '\n  Fixed version : ' + display_fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url, display_version);
