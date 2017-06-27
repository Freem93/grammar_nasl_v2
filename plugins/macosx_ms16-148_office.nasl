#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95810);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id(
    "CVE-2016-7257",
    "CVE-2016-7263",
    "CVE-2016-7264",
    "CVE-2016-7266",
    "CVE-2016-7268",
    "CVE-2016-7276",
    "CVE-2016-7290",
    "CVE-2016-7291",
    "CVE-2016-7298",
    "CVE-2016-7300"
  );
  script_bugtraq_id(
    94662,
    94668,
    94670,
    94671,
    94672,
    94720,
    94755,
    94769,
    94784
  );
  script_osvdb_id(
    148613,
    148625,
    148628,
    148632,
    148633,
    148635,
    148636,
    148637,
    148638,
    148639
  );
  script_xref(name:"MSFT", value:"MS16-148");
  script_xref(name:"IAVA", value:"2016-A-0345");

  script_name(english:"MS16-148: Security Update for Microsoft Office (3204068) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS or Mac
OS X host is missing a security update. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    Graphics Device Interface (GDI) component due to
    improper handling of objects in memory. A local attacker
    can exploit this, via a specially crafted application,
    to circumvent the Address Space Layout Randomization
    (ASLR) feature and disclose sensitive memory
    information. (CVE-2016-7257)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office software due to a failure to properly
    handle objects in memory. An unauthenticated, remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted Office file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2016-7263,
    CVE-2016-7298)

  - Multiple information disclosure vulnerabilities exist in
    Microsoft Office software due to an out-of-bounds memory
    read error. An unauthenticated, remote attacker can
    exploit these vulnerabilities by convincing a user to
    open a specially crafted Office file, resulting in the
    disclosure of memory contents. (CVE-2016-7264,
    CVE-2016-7268, CVE-2016-7276, CVE-2016-7290,
    CVE-2016-7291)

  - An arbitrary command execution vulnerability exists in
    Microsoft Office due to improper validation of registry
    settings when running embedded content. An
    unauthenticated, remote attacker can exploit this by
    convincing a user to open a specially crafted document
    file multiple times, resulting in a bypass of security
    restrictions and the execution of arbitrary commands.
    (CVE-2016-7266)

  - An elevation of privilege vulnerability exists in the
    Microsoft AutoUpdate (MAU) application due to improper
    validation of updates. A local attacker can exploit this
    by placing a specially crafted application in a location
    used by the update application, resulting in the ability
    to execute arbitrary code in a privileged context.
    (CVE-2016-7300)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-148");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac
2011, Microsoft Office 2016 for Mac, Microsoft Excel for Mac 2011,
Microsoft Excel 2016 for Mac, Microsoft Word for Mac 2011, Microsoft
Word 2016 for Mac, and Microsoft Auto Updater for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:auto_updater_for_mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports(
    "installed_sw/Office for Mac 2011",
    "installed_sw/Microsoft Outlook",
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

# Office 2011
apps = make_list(
  "Office for Mac 2011",
  "Microsoft Outlook",
  "Microsoft Excel",
  "Microsoft Word",
  "Microsoft PowerPoint",
  "Microsoft OneNote"
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
    if (version =~ "^14\.")
    {
      if (app !~ " for Mac 2011$") app_label += " for Mac 2011";
      fix = '14.7.1';
    }
    else
    {
      if (version =~ "^15\.") app_label += " for Mac 2016";
      fix = '15.29';
      fix_disp = '15.29 (161209)';
    }

    if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
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
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
