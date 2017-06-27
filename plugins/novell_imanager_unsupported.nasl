#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66035);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_name(english:"Novell iManager Unsupported Version");
  script_summary(english:"Checks version of Novell iManager");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running unsupported software.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Novell iManager prior to
version 2.7. Such versions are no longer covered under general or
extended support.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/lifecycle/");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of Novell iManager that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:imanager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_imanager_detect.nasl");
  script_require_keys("www/novell_imanager");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("datetime.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);

appname = "Novell iManager";

install = get_install_from_kb(appname:'novell_imanager', port:port, exit_on_fail:TRUE);
version = install['ver'];

url = build_url(port:port, qs:install['dir'] + '/');

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] < 7)
)
{
  register_unsupported_product(product_name:"Novell iManager",
                               cpe_base:"novell:imanager", version:version);

  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Supported version : 2.7\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
