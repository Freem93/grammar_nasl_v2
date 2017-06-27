#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91857);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/06/27 19:12:37 $");

  script_name(english:"Microsoft Office Unsupported Version Detection (Mac OS X)");
  script_summary(english:"Checks the Microsoft Office version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Microsoft Office.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Microsoft Office on the
remote Mac OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/lifecycle");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/gp/lifeoffice");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/gp/lifeselect");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Office that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:x:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008:mac");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports(
    "installed_sw/Office 2008 for Mac",
    "installed_sw/Microsoft Excel",
    "installed_sw/Microsoft Word",
    "installed_sw/Microsoft PowerPoint",
    "installed_sw/Microsoft OneNote"
  );
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# macosx_office_installed.nasl doesn't support versions before Office 2008
#   since 2008 was the first Universal binary version but we might
#   find the application installs (Word, Excel, etc) so we'll include those.
eos_dates = make_array(
  "10", "January 9, 2007",
  '11', "January 10, 2012",
  "12", "April 9, 2014",
  "14", "October 10, 2017",
  "15", "October 13, 2020"
);

apps = make_list(
  "Office 2008 for Mac",
  "Office for Mac 2011",
  "Microsoft Excel",
  "Microsoft Word",
  "Microsoft PowerPoint",
  "Microsoft OneNote"
);

report = "";

foreach app (apps)
{
  installs = get_installs(app_name:app);
  if (installs[0] != IF_OK || isnull(installs[1])) continue;
  foreach install (installs[1])
  {
    version = install["version"];
    path    = install["path"];
    app_label = app;
    if (version =~ "^10\.")
    {
      if (app !~ "Office") app_label += " v. X";
      eos_date = eos_dates['10'];
    }
    else if (version =~ "^11\.")
    {
      if (app !~ "Office") app_label += " 2004 for Mac";
      eos_date = eos_dates['11'];
    }
    else if (version =~ "^12\.")
    {
      if (app !~ "Office") app_label += " 2008 for Mac";
      eos_date = eos_dates['12'];
    }
#    else if (version =~ "^14\.")
#    {
#      if (app !~ "Office") app_label += " for Mac 2011";
#      eos_date = eos_dates['14'];
#    }
    else continue;

    register_unsupported_product(product_name:app_label, cpe_base:"microsoft:office", version:version);

    report +=
      '\n  Product             : ' + app_label +
      '\n  Installed version   : ' + version +
      '\n  Path                : ' + path +
      '\n  End of support date : ' + eos_date +
      '\n';
  }
}

if (report)
{
  report = "The following unsupported products were identified:" + report;
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Microsoft Office");
