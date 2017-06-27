#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70496);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id("CVE-2013-5688");
  script_bugtraq_id(62259, 62260);
  script_osvdb_id(97021, 97022);
  script_xref(name:"EDB-ID", value:"28191");

  script_name(english:"AjaXplorer < 5.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of remote web application.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote web server has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of AjaXplorer hosted on the remote web server is earlier
than 5.0.3.  It is, therefore, affected by the following two
vulnerabilities in the 'filemanagers/ajaxplorer/index.php' script:

  - A directory traversal vulnerability exists that allows
    an attacker to view files outside of the website's root
    directory.

  - Arbitrary files could be uploaded by an attacker because
    user input is not properly sanitized."
  );
  # http://web.archive.org/web/20130907075257/http://ajaxplorer.info/ajaxplorer-core-5-0-3/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b3f40fe");
  script_set_attribute(attribute:"solution", value:"Upgrade to AjaXplorer version 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ajaxplorer:ajaxplorer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ajaxplorer_detect.nasl");
  script_require_keys("www/ajaxplorer");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

install = get_install_from_kb(appname:'ajaxplorer', port:port, exit_on_fail:TRUE);

version = install['ver'];
base_url = build_url(qs:install['dir']+'/', port:port);

fixed_ver = '5.0.3';
if (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + base_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'AjaXplorer', base_url, version);
