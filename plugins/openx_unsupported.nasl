#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76313);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_name(english:"OpenX Source Unsupported Software Detection");
  script_summary(english:"Flags OpenX Source as unsupported.");

  script_set_attribute(attribute:"synopsis", value:"A web application hosted on the remote web server is unsupported.");
  script_set_attribute(attribute:"description", value:
"OpenX Source, an open source ad server application is no longer
maintained and is unsupported by the vendor.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://openx.com/press-releases/openx-sells-open-source-ad-serving-product/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f532340");
  # http://www.revive-adserver.com/blog/is-revive-adserver-compatible-with-openx-source/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cfca663");
  script_set_attribute(attribute:"solution", value:"Migrate to Revive Adserver or an alternative ad server application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openx:openx");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("openx_detect.nasl");
  script_require_keys("www/openx", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "openx",
  port         : port,
  exit_on_fail : TRUE
);

version = install['ver'];

register_unsupported_product(product_name:"OpenX",
                             cpe_base:"openx:openx", version:version);

if (report_verbosity > 0)
{
  report =
    '\n  URL     : ' + build_url(qs:install["dir"] + "/index.php", port:port) +
    '\n  Version : ' + version +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
