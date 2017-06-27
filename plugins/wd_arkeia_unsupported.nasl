#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74219);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"Western Digital Arkeia Virtual Appliance Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Western Digital
Arkeia Virtual Appliance.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
Western Digital Arkeia appliance on the remote host is no longer
supported by the vendor.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.wdc.com/arkeia/eol.asp");
  script_set_attribute(attribute:"solution", value:"Upgrade to an actively maintained version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wdc:arkeia_virtual_appliance");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("wd_arkeia_detect.nbin");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("www/wd_arkeia", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:TRUE);

install = get_install_from_kb(
  appname      : "wd_arkeia",
  port         : port,
  exit_on_fail : TRUE
);

app = 'Western Digital Arkeia';
install_url = build_url(port:port, qs:install["dir"]);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);

latest = '9.0.x / 9.1.x / 10.0.x / 10.1.x / 10.2.x';

eol_dates = make_array(
#  '^10\\.2', '2018/01/31',
#  '^10\\.1', '2017/08/31',
#  '^10\\.0', '2017/01/31',
#  '^9\\.1', '2016/01/31',
#  '^9\\.0', '2015/06/30',
  '^8\\.2', '2014/06/30',
  '^8\\.1', '2013/09/30',
  '^8\\.0', '2013/03/31',
  '^7\\.0', '2011/12/31',
  '^6\\.0', '2010/09/30',
  '^5\\.3', '2008/03/31',
  '^5\\.2', '2007/03/31',
  '^5\\.1', '2007/01/31',
  '^5\\.0', '2006/07/31',
  '^4\\.2', '2003/07/31'
);
unsupported = FALSE;

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

begin_ver = ver[0] + '.' + ver[1];

foreach v (keys(eol_dates))
{
  if (begin_ver =~ v)
  {
    unsupported = TRUE;
    break;
  }
}

if (unsupported)
{
  register_unsupported_product(product_name:app,
                               cpe_base:"wdc:arkeia_virtual_appliance", version:version);

  if (report_verbosity > 0)
  {
    report +=
      '\n  Product             : ' + app +
      '\n  URL                 : ' + install_url +
      '\n  Installed version   : ' + version +
      '\n  End of support date : ' + eol_dates[v] +
      '\n  Latest version      : ' + latest;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The " + app + " install at " + install_url + " is still supported.");
