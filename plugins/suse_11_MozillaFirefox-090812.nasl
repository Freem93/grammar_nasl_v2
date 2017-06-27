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
  script_id(41358);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664");

  script_name(english:"SuSE 11 Security Update : Mozilla Firefox (SAT Patch Number 1200)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 3.0.13 release, fixing some
security issues and bugs :

  - Security researcher Juan Pablo Lopez Yacubian reported
    that an attacker could call window.open() on an invalid
    URL which looks similar to a legitimate URL and then use
    document.write() to place content within the new
    document, appearing to have come from the spoofed
    location. Additionally, if the spoofed document was
    created by a document with a valid SSL certificate, the
    SSL indicators would be carried over into the spoofed
    document. An attacker could use these issues to display
    misleading location and SSL information for a malicious
    web page. (MFSA 2009-44 / CVE-2009-2654)

  - The browser engine in Mozilla Firefox before 3.0.13, and
    3.5.x before 3.5.2, allows remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly execute arbitrary code via vectors
    related to the TraceRecorder::snapshot function in
    js/src/jstracer.cpp, and unspecified other vectors.
    (MFSA 2009-45 / CVE-2009-2662)

  - libvorbis before r16182, as used in Mozilla Firefox
    before 3.0.13 and 3.5.x before 3.5.2 and other products,
    allows context-dependent attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly execute arbitrary code via a crafted .ogg file.
    (CVE-2009-2663 / MFSA 2009-45)

  - The js_watch_set function in js/src/jsdbgapi.cpp in the
    JavaScript engine in Mozilla Firefox before 3.0.13, and
    3.5.x before 3.5.2, allows remote attackers to cause a
    denial of service (assertion failure and application
    exit) or possibly execute arbitrary code via a crafted
    .js file, related to a 'memory safety bug.'.
    (CVE-2009-2664 / MFSA 2009-45)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2662.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2663.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2664.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1200.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gconf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gconf2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libidl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:orbit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:orbit2-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/12");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-3.0.13-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-3.0.13-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gconf2-2.24.0-7.5")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libidl-0.8.11-2.14")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-translations-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"orbit2-2.14.16-2.16")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-3.0.13-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-translations-3.0.13-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gconf2-2.24.0-7.5")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gconf2-32bit-2.24.0-7.5")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libidl-0.8.11-2.14")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libidl-32bit-0.8.11-2.14")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"orbit2-2.14.16-2.16")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"orbit2-32bit-2.14.16-2.16")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-3.0.13-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-translations-3.0.13-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"gconf2-2.24.0-7.5")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libidl-0.8.11-2.14")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-translations-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"orbit2-2.14.16-2.16")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"gconf2-32bit-2.24.0-7.5")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libidl-32bit-0.8.11-2.14")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-xulrunner190-32bit-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"orbit2-32bit-2.14.16-2.16")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"gconf2-32bit-2.24.0-7.5")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libidl-32bit-0.8.11-2.14")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.13-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"orbit2-32bit-2.14.16-2.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
