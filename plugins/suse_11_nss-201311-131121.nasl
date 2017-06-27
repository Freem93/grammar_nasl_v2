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
  script_id(71172);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/03 12:13:22 $");

  script_cve_id("CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : mozilla-nspr, mozilla-nss (SAT Patch Numbers 8572 / 8573)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla NSPR and NSS were updated to fix various security bugs that
could be used to crash the browser or potentially execute code.

Mozilla NSPR 4.10.2 has the following bug fixes :

  - Bug 770534: Possible pointer overflow in
    PL_ArenaAllocate(). Fixed by Pascal Cuoq and Kamil
    Dudka.

  - Bug 888546: ptio.c:PR_ImportUDPSocket doesn't work.
    Fixed by Miloslav Trmac.

  - Bug 915522: VS2013 support for NSPR. Fixed by Makoto
    Kato.

  - Bug 927687: Avoid unsigned integer wrapping in
    PL_ArenaAllocate. (CVE-2013-5607) Mozilla NSS 3.15.3 is
    a patch release for NSS 3.15 and includes the following
    bug fixes :

  - Bug 925100: Ensure a size is <= half of the maximum
    PRUint32 value. (CVE-2013-1741)

  - Bug 934016: Handle invalid handshake packets.
    (CVE-2013-5605)

  - Bug 910438: Return the correct result in CERT_VerifyCert
    on failure, if a verifyLog isn't used. (CVE-2013-5606)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1741.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5605.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5606.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5607.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8572 / 8573 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/03");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libfreebl3-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nspr-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-tools-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-tools-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libfreebl3-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libsoftokn3-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nspr-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-tools-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-tools-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libfreebl3-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nspr-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-tools-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libfreebl3-32bit-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nss-32bit-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.3-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libfreebl3-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libsoftokn3-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nspr-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-tools-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libfreebl3-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libsoftokn3-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nss-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.3-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.3-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
