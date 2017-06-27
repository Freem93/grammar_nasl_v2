#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62221);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/04/14 16:30:50 $");

  script_name(english:"Adobe Photoshop for Mac Unsupported Version Detection");
  script_summary(english:"Checks versions gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an unsupported version of Adobe
Photoshop.");
  script_set_attribute(attribute:"description", value:
"At least one version of Adobe Photoshop installed on the remote Mac
OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe Photoshop that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

get_kb_item_or_exit("installed_sw/Adobe Photoshop");

app = 'Adobe Photoshop';

install=get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['name'];
path    = install['path'];
version = install['version'];

if (ver_compare(ver:version, fix:'16.0', strict:FALSE) < 0)
{
  register_unsupported_product(product_name:'Adobe Photoshop',
                                 version:version, cpe_base:"adobe:photoshop");

  if (report_verbosity > 0)
  {
    report = '\n  Product            : ' + product +
             '\n  Path               : ' + path +
             '\n  Installed version  : ' + version +
             '\n  Supported versions : CC 2015';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
