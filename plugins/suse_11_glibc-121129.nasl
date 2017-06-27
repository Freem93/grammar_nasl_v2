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
  script_id(64150);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480");

  script_name(english:"SuSE 11.2 Security Update : glibc (SAT Patch Number 7110)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This collective update for the GNU C library (glibc) provides the
following fixes :

  - Fix strtod integer/buffer overflows. (bnc#775690,
    CVE-2012-3480)

  - Fix vfprintf handling of many format specifiers.
    (bnc#770891, CVE-2012-3404 / CVE-2012-3405 /
    CVE-2012-3406)

  - Fix pthread_cond_timedwait stack unwinding. (bnc#750741,
    bnc#777233)

  - Improve fix for dynamic library unloading. (bnc#783060)

  - Fix resolver when first query fails, but second one
    succeeds. (bnc#767266)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3406.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3480.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7110.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-devel-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-i18ndata-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"glibc-locale-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"nscd-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i686", reference:"glibc-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i686", reference:"glibc-devel-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-devel-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-i18ndata-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-locale-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"nscd-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-devel-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-html-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-i18ndata-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-info-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-locale-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-profile-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"nscd-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.43.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
