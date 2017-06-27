#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99313);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0207");
  script_bugtraq_id(97463);
  script_osvdb_id(155366);
  script_xref(name:"MSKB", value:"3212218");

  script_name(english:"Security Update for Microsoft Office (April 2017) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by a spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS or Mac
OS X host is missing a security update. It is, therefore, affected by
a spoofing vulnerability in Microsoft Outlook due to improper
validation of input passed via HTML tags. An unauthenticated, remote
attacker can exploit this, by sending an email with specific HTML
tags, to display a malicious authentication prompt and gain access to
a user's authentication information or login credentials.");
  # https://support.microsoft.com/en-us/help/3212218/description-of-the-security-update-for-office-for-mac-2011-14-7-3-apri
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?e6f0a227");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Microsoft Outlook for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook_for_mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys(
    "Host/MacOSX/Version",
    "installed_sw/Microsoft Outlook"
  );

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = "Microsoft Outlook";
report = "";

installs = get_installs(app_name:app);
if (isnull(installs[1])) audit(AUDIT_NOT_INST, app);

fix = '14.7.3';

foreach install (installs[1])
{
  version = install['version'];
  path    = install['path'];
  app_label = app;
  if (version =~ "^14\.")
  {
    if (app !~ " for Mac 2011$") app_label += " for Mac 2011";

    if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
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
