#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57122);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_name(english:"SuSE 11.1 Security Update : libfreebl3 (SAT Patch Number 5138)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update updates Mozilla NSS to 3.12.11.

The update marks the compromised DigiNotar Certificate Authority as
untrusted

For more information read :

MFSA 2011-34

  - update to 3.12.10

  - root CA changes

  - filter certain bogus certs (bmo#642815)

  - fix minor memory leaks

  - other bugfixes

  - update to 3.12.9

  - fix minor memory leaks (bmo#619268)

  - fix crash in nss_cms_decoder_work_data (bmo#607058)

  - fix crash in certutil (bmo#620908)

  - handle invalid argument in JPAKE (bmo#609068)

  - J-PAKE support (API requirement for Firefox >= 4.0b8)

  - replaced expired PayPal test certificate (fixing
    testsuite)

  - removed DigiNotar root certifiate from trusted db
    (bmo#682927) This update also brings the prerequired
    Mozilla NSPR to version 4.8.9.

  - update to 4.8.9

  - update to 4.8.8

  - support IPv6 on Android (bmo#626866)

  - use AI_ADDRCONFIG for loopback hostnames (bmo#614526)

  - support SDP sockets (bmo#518078)

  - support m32r architecture (bmo#635667)

  - use atomic functions on ARM (bmo#626309)

  - some other fixes not affecting the Linux platform"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714931"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5138.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libfreebl3-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nspr-4.8.9-1.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nss-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nss-tools-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libfreebl3-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libfreebl3-32bit-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-4.8.9-1.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8.9-1.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-tools-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libfreebl3-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nspr-4.8.9-1.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nss-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nss-tools-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libfreebl3-32bit-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-nspr-32bit-4.8.9-1.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-nss-32bit-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libfreebl3-32bit-3.12.11-3.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8.9-1.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.11-3.2.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
