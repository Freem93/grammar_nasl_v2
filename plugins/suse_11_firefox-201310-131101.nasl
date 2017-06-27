#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70933);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/24 03:40:13 $");

  script_cve_id("CVE-2013-1739", "CVE-2013-5590", "CVE-2013-5595", "CVE-2013-5597", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5604");

  script_name(english:"SuSE 11.3 Security Update : Mozilla Firefox (SAT Patch Number 8491)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to the 17.0.10ESR release, which
fixes various bugs and security issues :

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2013-93)

    Jesse Ruderman and Christoph Diehl reported memory
    safety problems and crashes that affect Firefox ESR 17,
    Firefox ESR 24, and Firefox 24. (CVE-2013-5590)

    Carsten Book reported a crash fixed in the NSS library
    used by Mozilla-based products fixed in Firefox 25,
    Firefox ESR 24.1, and Firefox ESR 17.0.10.
    (CVE-2013-1739)

  - Security researcher Abhishek Arya (Inferno) of the
    Google Chrome Security Team used the Address Sanitizer
    tool to discover an access violation due to
    uninitialized data during Extensible Stylesheet Language
    Transformation (XSLT) processing. This leads to a
    potentially exploitable crash. (MFSA 2013-95 /
    CVE-2013-5604)

  - Compiler Engineer Dan Gohman of Google discovered a flaw
    in the JavaScript engine where memory was being
    incorrectly allocated for some functions and the calls
    for allocations were not always properly checked for
    overflow, leading to potential buffer overflows. When
    combined with other vulnerabilities, these flaws could
    be potentially exploitable. (MFSA 2013-96 /
    CVE-2013-5595)

  - Security researcher Byoungyoung Lee of Georgia Tech
    Information Security Center (GTISC) used the Address
    Sanitizer tool to discover a use-after-free during state
    change events while updating the offline cache. This
    leads to a potentially exploitable crash. (MFSA 2013-98
    / CVE-2013-5597)

  - Security researcher Nils used the Address Sanitizer tool
    while fuzzing to discover missing strong references in
    browsing engine leading to use-after-frees. This can
    lead to a potentially exploitable crash. (MFSA 2013-100)

  - ASAN heap-use-after-free in
    nsIPresShell::GetPresContext() with canvas, onresize and
    mozTextStyle. (CVE-2013-5599)

  - ASAN use-after-free in
    nsIOService::NewChannelFromURIWithProxyFlags with Blob
    URL. (CVE-2013-5600)

  - ASAN use-after free in GC allocation in
    nsEventListenerManager::SetEventHandler. (CVE-2013-5601)

  - Security researcher Nils used the Address Sanitizer tool
    while fuzzing to discover a memory corruption issue with
    the JavaScript engine when using workers with direct
    proxies. This results in a potentially exploitable
    crash. (MFSA 2013-101 / CVE-2013-5602)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-93.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-95.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-96.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-98.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5595.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5599.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5602.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5604.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8491.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-17.0.10esr-0.7.4")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.12.41")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-17.0.10esr-0.7.4")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-17.0.10esr-0.7.4")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.12.41")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.10esr-0.7.4")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-17.0.10esr-0.7.4")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-branding-SLED-7-0.12.41")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-17.0.10esr-0.7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
