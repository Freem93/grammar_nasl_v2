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
  script_id(81697);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/28 17:02:45 $");

  script_cve_id("CVE-2015-0822", "CVE-2015-0827", "CVE-2015-0831", "CVE-2015-0835", "CVE-2015-0836");

  script_name(english:"SuSE 11.3 Security Update : Mozilla Firefox (SAT Patch Number 10373)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to version 31.5.0 ESR to fix five
security issues.

These security issues have been fixed :

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 31.5 allowed remote
    attackers to cause a denial of service (memory
    corruption and application crash) or possibly execute
    arbitrary code via unknown vectors. (bnc#917597).
    (CVE-2015-0836)

  - Heap-based buffer overflow in the mozilla::gfx::CopyRect
    function in Mozilla Firefox before 31.5 allowed remote
    attackers to obtain sensitive information from
    uninitialized process memory via a malformed SVG
    graphic. (bnc#917597). (CVE-2015-0827)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 36.0 allowed remote
    attackers to cause a denial of service (memory
    corruption and application crash) or possibly execute
    arbitrary code via unknown vectors. (bnc#917597).
    (CVE-2015-0835)

  - Use-after-free vulnerability in the
    mozilla::dom::IndexedDB::IDBObjectStore::CreateIndex
    function in Mozilla Firefox before 31.5 allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via crafted content
    that is improperly handled during IndexedDB index
    creation. (bnc#917597). (CVE-2015-0831)

  - The Form Autocompletion feature in Mozilla Firefox
    before 31.5 allowed remote attackers to read arbitrary
    files via crafted JavaScript code. (bnc#917597).
    (CVE-2015-0822)

These non-security issues have been fixed :

  - Reverted desktop file name back to
    MozillaFirefox.desktop. (bnc#916196, bnc#917100)

  - Obsolete subpackages of firefox-gcc47 from SLE11-SP1/2,
    that caused problems when upgrading to SLE11-SP3
    (bnc#917300)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=916196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=917100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=917300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=917597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0827.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0836.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10373.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-31.5.0esr-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-31.5.0esr-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-31.5.0esr-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-31.5.0esr-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-31.5.0esr-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-31.5.0esr-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
