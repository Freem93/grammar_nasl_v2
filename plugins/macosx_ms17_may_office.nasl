#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100295);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/19 14:20:48 $");

  script_cve_id("CVE-2017-0254");
  script_bugtraq_id(98101);
  script_osvdb_id(157256);
  script_xref(name:"MSKB", value:"3212221");

  script_name(english:"Security Update for Microsoft Office (May 2017) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS or Mac
OS X host is missing a security update. It is, therefore, affected by
a remote code execution vulnerability due to a failure to properly
handle objects in memory. An unauthenticated, remote attacker can
exploit this, by convincing a user to open a specially crafted Office
document or visit a specially crafted website, to execute arbitrary
code in the context of the current user.");
  # https://support.microsoft.com/en-us/help/3212221/description-of-the-security-update-for-office-for-mac-2011-14-7-4-may-
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?bdf80998");
  # https://support.office.com/en-us/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?68489292");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0254
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?afcf0103");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Microsoft Office for Mac 2011 and
Microsoft Office 2016 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports(
    "installed_sw/Office for Mac 2011",
    "installed_sw/Microsoft Outlook",
    "installed_sw/Microsoft Excel",
    "installed_sw/Microsoft Word",
    "installed_sw/Microsoft PowerPoint",
    "installed_sw/Microsoft OneNote",
    "installed_sw/Microsoft Lync"
  );

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# Office 2011
apps = make_list(
  "Office for Mac 2011",
  "Microsoft Outlook",
  "Microsoft Excel",
  "Microsoft Word",
  "Microsoft PowerPoint",
  "Microsoft OneNote",
  "Microsoft Lync"
);

report = "";

foreach app (apps)
{
  installs = get_installs(app_name:app);
  if (isnull(installs[1])) continue;
  foreach install (installs[1])
  {
    version = install['version'];
    path    = install['path'];
    app_label = app;
    fix = NULL;
    fix_disp = NULL;
    if (version =~ "^14\.")
    {
      if (app !~ " for Mac 2011$") app_label += " for Mac 2011";

      if (app =~ "Word" || app =~ "Excel")
        fix = '14.7.4';
      else if (app =~ "Lync")
        fix = '14.4.3';
    }
    else
    {
      if (version =~ "^15\.") app_label += " for Mac 2016";
      fix = '15.34.0';
      fix_disp = '15.34 (17051500)';
    }

    if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Product           : ' + app_label +
        '\n  Installed version : ' + version;

      if (!empty_or_null(fix_disp))
      {
        report += '\n  Fixed version     : ' + fix_disp;
        fix_disp = '';
      }
      else report += '\n  Fixed version     : ' + fix;

      os = get_kb_item("Host/MacOSX/Version");

      if (os =~ "^Mac OS X 10\.[0-9](\.|$)" && app_label =~ " for Mac 2016$")
        report += '\n  Note              : Update will require Mac OS X 10.10.0 or later.\n';
      else report += '\n';
    }
  }
}

# Report findings.
if (!empty(report))
{
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_HOST_NOT, "affected");
