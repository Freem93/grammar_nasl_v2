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
  script_id(77599);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/10/03 15:38:48 $");

  script_cve_id("CVE-2014-1562", "CVE-2014-1567");

  script_name(english:"SuSE 11.3 Security Update : MozillaFirefox (SAT Patch Number 9687)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 24.8.0ESR release, fixing security
issues and bugs.

Only some of the published security advisories affect the Mozilla
Firefox 24ESR codestream :

  - Security researcher regenrecht reported, via
    TippingPoint's Zero Day Initiative, a use-after-free
    during text layout when interacting with the setting of
    text direction. This results in a use-after-free which
    can lead to arbitrary code execution. (MFSA 2014-72 /
    CVE-2014-1567)

  - Mozilla developers and community identified and fixed
    several memory safety bugs in the browser engine used in
    Firefox and other Mozilla-based products. Some of these
    bugs showed evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2014-67)

  - Jan de Mooij reported a memory safety problem that
    affects Firefox ESR 24.7, ESR 31 and Firefox 31.
    (CVE-2014-1562) More information is referenced on:
    https://www.mozilla.org/security/announce/ ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-67.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-72.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1567.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9687.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-24.8.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-24.8.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libfreebl3-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libsoftokn3-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nspr-4.10.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-tools-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-24.8.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-24.8.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-4.10.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-tools-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-24.8.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-24.8.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libfreebl3-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libsoftokn3-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nspr-4.10.7-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-tools-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libfreebl3-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libsoftokn3-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.7-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nss-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.16.4-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.16.4-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
