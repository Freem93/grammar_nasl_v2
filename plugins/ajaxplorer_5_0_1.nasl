#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70495);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/18 20:49:36 $");

  script_cve_id("CVE-2013-4267");
  script_bugtraq_id(60863);
  script_osvdb_id(94692, 94826, 94830);

  script_name(english:"AjaXplorer < 5.0.1 Multiple Command Execution Vulnerabilities");
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
than 5.0.1.  It is, therefore, affected by multiple command execution
vulnerabilities in the following plugins:

  - File System Standard Plugin (access.fs)
  - Power FS Plugin (action.powerfs)
  - Subversion Repository Plugin (meta.svn)

The plugins above are installed and enabled in the default installation
except for the Power FS plugin, which is installed but not enabled by
default."
  );
  script_set_attribute(attribute:"see_also", value:"http://pyd.io/ajaxplorer-5-0-1/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q3/28");
  script_set_attribute(attribute:"solution", value:"Upgrade to AjaXplorer version 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ajaxplorer:ajaxplorer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

fixed_ver = '5.0.1';
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
