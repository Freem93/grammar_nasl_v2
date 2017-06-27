#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71458);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/02/25 21:53:14 $");

  script_name(english:"Nessus Unsupported Version Detection");
  script_summary(english:"Checks the Nessus version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Nessus.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable Nessus on the
remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://discussions.nessus.org/thread/6371"); # Nessus 4.x EOL
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Tenable Nessus that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("nessus_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_require_keys("installed_sw/nessus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

get_install_count(app_name:"nessus", exit_if_zero:TRUE);

port = get_http_port(default:8834);

install = get_install_from_kb(appname:"nessus", port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_loc = build_url(port:port, qs:dir + '/');

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Nessus", install_loc);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 6)
{
  register_unsupported_product(product_name:"Tenable Nessus", version:version,
                               cpe_base:"tenable:nessus");

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Supported versions : 6.x' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'The Nessus ' + version + ' server listening on port ' + port + ' is currently supported.');
