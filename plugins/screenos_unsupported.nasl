#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74379);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Unsupported ScreenOS Operating System");
  script_summary(english:"Checks for EOL versions.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an obsolete operating system.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ScreenOS operating system on the remote
host is obsolete and is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/eol/screenos.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported version of ScreenOS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb_base  = "Host/Juniper/ScreenOS/";
display_version = get_kb_item_or_exit(kb_base + "display_version");
version         = get_kb_item_or_exit(kb_base + "version");

latest = '6.3';
eol = make_array(
  #"6.3", "2019-12-31",
  "6.2", "2013-12-31",
  "6.1", "2012-01-28",
  "6.0", "2011-04-19",
  "5.4", "2013-12-31"
);

match = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)(?:[^0-9]|$)");
release = NULL;

if (isnull(match[1]))
  exit(1, 'Error parsing version: ' + version);
else
  release = match[1];

eol_date = NULL;
# Versions 0.x to 5.3.x aren't listed on the ScreenOS EOL page but are presumably unsupported
if (version =~ "^[0-4]\." || version =~ "^5\.[0-3]\.")
  eol_date = 'unknown';
else
  eol_date = eol[release];

if (isnull(eol_date)) exit(0, 'ScreenOS ' + display_version + ' is still supported.');

set_kb_item(name:"Host/Juniper/ScreenOS/unsupported", value:TRUE);

register_unsupported_product(product_name:"Juniper ScreenOS", cpe_class:CPE_CLASS_OS,
                             cpe_base:"juniper:screenos", version:tolower(version));

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  EOL date          : ' + eol_date +
    '\n  Latest version    : ' + latest + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
