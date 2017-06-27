#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97739);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0020",
    "CVE-2017-0027",
    "CVE-2017-0029",
    "CVE-2017-0030",
    "CVE-2017-0031",
    "CVE-2017-0105",
    "CVE-2017-0129"
  );
  script_bugtraq_id(
    96043,
    96045,
    96050,
    96051,
    96052,
    96746,
    96752
  );
  script_osvdb_id(
    153732,
    153733,
    153734,
    153737,
    153738,
    153739,
    153741
  );
  script_xref(name:"MSFT", value:"MS17-014");
  script_xref(name:"MSKB", value:"4013241");
  script_xref(name:"IAVA", value:"2017-A-0060");

  script_name(english:"MS17-014: Security Update for Microsoft Office (4013241) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS or Mac
OS X host is missing a security update. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist
    in Microsoft Office software due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to open a
    specially crafted document file, to execute arbitrary
    code in the context of the current user. (CVE-2017-0020,
    CVE-2017-0030, CVE-2017-0031)

  - An information disclosure vulnerability exists in
    Microsoft Office due to improper disclosure of memory
    contents. An unauthenticated, remote attacker can
    exploit this to disclose sensitive system memory
    information by convincing a user to open a specially
    crafted document file. (CVE-2017-0027)

  - A denial of service vulnerability exists in Microsoft
    Office that allows an unauthenticated, remote attacker
    to cause Office to stop responding by convincing a user
    to open a specially crafted document file.
    (CVE-2017-0029)

  - An out-of-bounds read error exists in Microsoft Office
    due to an uninitialized variable. A local attacker can
    exploit this to disclose memory contents by opening a
    specially crafted document file. (CVE-2017-0105)

  - A flaw exists in Microsoft Lync for Mac due to improper
    validation of X.509 certificates. A man-in-the-middle
    attacker can exploit this, by spoofing a TLS/SSL server
    via a certificate that appears valid, to disclose or
    manipulate transmitted data. (CVE-2017-0129)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS17-014");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for
Mac 2011, Microsoft Office 2016 for Mac, Microsoft Excel for Mac 2011,
Microsoft Excel 2016 for Mac, Microsoft Word for Mac 2011, and
Microsoft Lync for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
        fix = '14.7.3';
      else if (app =~ "Lync")
        fix = '14.4.3';
    }
    else
    {
      if (version =~ "^15\.") app_label += " for Mac 2016";
      fix = '15.32';
      fix_disp = '15.32 (17030901)';
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
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
