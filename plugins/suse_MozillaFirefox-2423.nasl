#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29358);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6505", "CVE-2006-6506", "CVE-2006-6507");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 2423)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings MozillaFirefox to the security update release
1.5.0.9, including the following security fixes.

http://www.mozilla.org/projects/security/known-vulnerabilities.html

  - Crashes with evidence of memory corruption were fixed in
    the layout engine. CVE-2006-6498 / MFSA 2006-68: Crashes
    with evidence of memory corruption were fixed in the
    JavaScript engine. CVE-2006-6499 / MFSA 2006-68: Crashes
    regarding floating point usage were fixed. CVE-2006-6500
    / MFSA 2006-69: This issue only affects Windows systems,
    Linux is not affected. CVE-2006-6501 / MFSA 2006-70: A
    privilege escalation using a watch point was fixed.
    CVE-2006-6502 / MFSA 2006-71: A LiveConnect crash
    finalizing JS objects was fixed. CVE-2006-6503 / MFSA
    2006-72: A XSS problem caused by setting img.src to
    javascript: URI was fixed. CVE-2006-6504 / MFSA 2006-73:
    A Mozilla SVG Processing Remote Code Execution was
    fixed. CVE-2006-6505 / MFSA 2006-74: Some Mail header
    processing heap overflows were fixed. CVE-2006-6506 /
    MFSA 2006-75: The RSS Feed-preview referrer leak was
    fixed. CVE-2006-6507 / MFSA 2006-76: A XSS problem using
    outer window's Function object was fixed. (CVE-2006-6497
    / MFSA 2006-68)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6499.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6505.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6507.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2423.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:0, reference:"MozillaFirefox-1.5.0.9-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"MozillaFirefox-translations-1.5.0.9-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"MozillaFirefox-1.5.0.9-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"MozillaFirefox-translations-1.5.0.9-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
