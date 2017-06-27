#
# (C) Tenable Network Security, Inc.
#

include ("compat.inc");

if (description)
{
  script_id(62220);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/06/26 17:34:37 $");

  script_name(english:"Adobe Photoshop for Mac Installed");
  script_summary(english:"Gets the Adobe Photoshop version from system_profiler.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a graphics editing application.");
  script_set_attribute(attribute:"description", value:
"Adobe Photoshop, an image editing application, is installed on the Mac
OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/photoshop.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "macosx_eval_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "Host/MacOSX/packages");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("macosx_software_eval_funcs.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = "Adobe Photoshop";

pkg_found=osx_find_installs(package:app,icase:FALSE,partial:TRUE,single:TRUE);

if (empty_or_null(pkg_found))
  audit(AUDIT_NOT_INST,app);

install=get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['name'];
path    = install['path'];
version = install['version'];

if (report_verbosity > 0)
{
  report = '\n  Product           : ' + product +
           '\n  Path              : ' + path +
           '\n  Installed version : ' + version;

  security_note(port:0, extra:report);
}
else security_note(0);
exit(0);
