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
  script_id(71307);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/10 14:13:50 $");

  script_cve_id("CVE-2012-4412", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4788");

  script_name(english:"SuSE 11.2 Security Update : glibc (SAT Patch Number 8335)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc contains the following fixes :

  - Fix integer overflows in malloc. (CVE-2013-4332,
    bnc#839870)

  - Fix buffer overflow in glob. (bnc#691365)

  - Fix buffer overflow in strcoll. (CVE-2012-4412,
    bnc#779320)

  - Update mount flags in <sys/mount.h>. (bnc#791928)

  - Fix buffer overrun in regexp matcher. (CVE-2013-0242,
    bnc#801246)

  - Fix memory leaks in dlopen. (bnc#811979)

  - Fix stack overflow in getaddrinfo with many results.
    (CVE-2013-1914, bnc#813121)

  - Fix check for XEN build in glibc_post_upgrade that
    causes missing init re-exec. (bnc#818628)

  - Don't raise UNDERFLOW in tan/tanf for small but normal
    argument. (bnc#819347)

  - Properly cross page boundary in SSE4.2 implementation of
    strcmp. (bnc#822210)

  - Fix robust mutex handling after fork. (bnc#827811)

  - Fix missing character in IBM-943 charset. (bnc#828235)

  - Fix use of alloca in gaih_inet. (bnc#828637)

  - Initialize pointer guard also in static executables.
    (CVE-2013-4788, bnc#830268)

  - Fix readdir_r with long file names. (CVE-2013-4237,
    bnc#834594)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=691365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4332.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4788.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8335.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-devel-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-i18ndata-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-locale-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"nscd-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i686", reference:"glibc-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i686", reference:"glibc-devel-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-devel-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-i18ndata-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-locale-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"nscd-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-devel-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-html-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-i18ndata-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-info-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-locale-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-profile-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"nscd-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.45.49.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.45.49.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
