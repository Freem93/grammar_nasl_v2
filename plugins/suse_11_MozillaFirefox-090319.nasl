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
  script_id(41352);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-0040", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");

  script_name(english:"SuSE 11 Security Update : MozillaFirefox (SAT Patch Number 656)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox browser is updated to version 3.0.7 fixing various
security and stability issues.

  - Mozilla developers identified and fixed several
    stability bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these crashes
    showed evidence of memory corruption under certain
    circumstances and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2009-07 / CVE-2009-0771 / CVE-2009-0772 /
    CVE-2009-0773 / CVE-2009-0774)

  - An anonymous researcher, via TippingPoint's Zero Day
    Initiative program, reported a vulnerability in
    Mozilla's garbage collection process. The vulnerability
    was caused by improper memory management of a set of
    cloned XUL DOM elements which were linked as a parent
    and child. After reloading the browser on a page with
    such linked elements, the browser would crash when
    attempting to access an object which was already
    destroyed. An attacker could use this crash to run
    arbitrary code on the victim's computer. (MFSA 2009-08 /
    CVE-2009-0775)

  - Mozilla security researcher Georgi Guninski reported
    that a website could use nsIRDFService and a
    cross-domain redirect to steal arbitrary XML data from
    another domain, a violation of the same-origin policy.
    This vulnerability could be used by a malicious website
    to steal private data from users authenticated to the
    redirected website. (MFSA 2009-09 / CVE-2009-0776)

  - libpng maintainer Glenn Randers-Pehrson reported several
    memory safety hazards in PNG libraries used by Mozilla.
    These vulnerabilities could be used by a malicious
    website to crash a victim's browser and potentially
    execute arbitrary code on their computer. libpng was
    upgraded to a version which contained fixes for these
    flaws. (MFSA 2009-10 / CVE-2009-0040)

  - Mozilla contributor Masahiro Yamada reported that
    certain invisible control characters were being decoded
    when displayed in the location bar, resulting in fewer
    visible characters than were present in the actual
    location. An attacker could use this vulnerability to
    spoof the location bar and display a misleading URL for
    their malicious web page. (MFSA 2009-11 / CVE-2009-0777)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0771.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0773.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0777.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 656.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-3.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-3.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-translations-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-3.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-translations-3.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-3.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-translations-3.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-translations-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-xulrunner190-32bit-1.9.0.7-1.1.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.7-1.1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
