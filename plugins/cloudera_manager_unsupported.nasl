#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76259);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_name(english:"Cloudera Manager Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of Cloudera Manager.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cloudera Manager web
application running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.cloudera.com/content/cloudera/en/legal/support-lifecycle-policy.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?224c5a56");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Cloudera Manager that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudera:cloudera_manager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cloudera_manager_detect.nbin");
  script_require_keys("installed_sw/Cloudera Manager");
  script_require_ports("Services/www", 7180, 7183);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cloudera Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:7183);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];
install_url = build_url(port:port, qs:dir);

latest = "5.0.x";

eol_dates = make_array(
  "^3\.7", "2013/06/20",
  "^4\.0", "2014/09/01",
  "^4\.1", "2014/09/01",
  "^4\.5", "2015/08/09",
  "^4\.6", "2015/08/09",
  "^4\.7", "2015/08/09",
  "^4\.8", "2015/08/09"
#  "^5\.0", "TBD"
);

unsupported = FALSE;

foreach v (keys(eol_dates))
{
  if (version =~ v)
  {
    unsupported = TRUE;
    break;
  }
}

if (unsupported)
{
  register_unsupported_product(product_name:"Cloudera Manager",
                               version:version, cpe_base:"cloudera:cloudera_manager");

  if (report_verbosity > 0)
  {
    report =
      '\n  Product             : ' + app +
      '\n  URL                 : ' + install_url +
      '\n  Installed version   : ' + version +
      '\n  End of support date : ' + eol_dates[v] +
      '\n  Latest version      : ' + latest;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  exit(0, "The " + app + " install at " + install_url + " is version " + version + " and is still supported.");
