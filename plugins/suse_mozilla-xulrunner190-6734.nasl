#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49898);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/06/14 20:02:12 $");

  script_cve_id("CVE-2009-3979", "CVE-2009-3981", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");

  script_name(english:"SuSE 10 Security Update : XULRunner (ZYPP Patch Number 6734)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla XULRunner engine was updated to version 1.9.0.16, fixing
lots of bugs and various security issues.

The following issues were fixed :

  - Crashes with evidence of memory corruption (1.9.0.16).
    (MFSA 2009-65 / CVE-2009-3979 / CVE-2009-3981)

  - (bmo#487872) NTLM reflection vulnerability. (MFSA
    2009-68 / CVE-2009-3983)

  - (bmo#521461,bmo#514232) Location bar spoofing
    vulnerabilities. (MFSA 2009-69 / CVE-2009-3984 /
    CVE-2009-3985)

  - (bmo#522430) Privilege escalation via chrome
    window.opener. (MFSA 2009-70 / CVE-2009-3986)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-65.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-69.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-70.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3984.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3985.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3986.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6734.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-translations-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-translations-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.16-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.16-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
