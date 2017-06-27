#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83813);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_bugtraq_id(74582);
  script_osvdb_id(121897, 121898);

  script_name(english:"eFront < 3.6.15.4 Build 18023 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of eFront.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the version of eFront running on
the remote web server is affected by multiple vulnerabilities :

  - A path traversal vulnerability exists due to improper
    sanitization of user-supplied input to the 'file'
    parameter of the view_file.php script. A remote attacker
    can exploit this, via a specially crafted request, to
    gain access to arbitrary files and disclose sensitive
    information. (VulnDB 121897)

  - Multiple SQL injection vulnerabilities exist due to
    improper sanitization of user-supplied input to the
    'new_less_id' parameter of the new_sidebar.php script. A
    remote attacker can exploit these vulnerabilities to
    manipulate the database.

  - A potential PHP object injection issue exists in the
    copy.php script.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.securenetwork.it/docs/advisory/SN-15-02_eFront.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.efrontlearning.net/download");
  script_set_attribute(attribute:"solution", value:
"Upgrade to eFront version 3.6.15.4 Build 18023 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:efrontlearning:efront");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("efront_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/eFront");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "eFront";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);
build = install['Build'];

fix_ver   = '3.6.15';
fix_build = 18023;
vuln = 0;
note = NULL;

if (build == UNKNOWN_VER)
{
  if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0)
  {
    if (report_paranoia == 2)
    {
      note = '\n' +
       '\n  Note that the build number could not be determined and it is'+
       '\n  recommend you log into the ' +app+ ' administrative interface and' +
       '\n  ensure you have the latest build installed.';
      vuln++;
    }
    else
      exit(0, "Nessus was unable to determine if the " + version + " version of " + app+ " installed at " + install_url + " is affected as the build number is " + build);
  }
}

if (
  ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1 ||
  (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0 &&
   build < fix_build)
  )
{
  vuln++;
}

if (vuln)
{
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);
  if (report_verbosity > 0)
  {
    if (empty_or_null(note)) note = '';
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : ' + fix_ver + ' Build ' + fix_build +
      note +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version + " Build " + build);
