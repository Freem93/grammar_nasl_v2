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
  script_id(81295);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2012-6656", "CVE-2014-6040", "CVE-2014-9402");

  script_name(english:"SuSE 11.3 Security Update : glibc (SAT Patch Number 10259)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"glibc has been updated to fix security issues and bugs :

  - Fix crashes on invalid input in IBM gconv modules.
    (CVE-2014-6040 / CVE-2012-6656, bsc#894553, bsc#894556,
    GLIBC BZ #17325, GLIBC BZ #14134)

  - Avoid infinite loop in nss_dns getnetbyname.
    (CVE-2014-9402)

  - Don't touch user-controlled stdio locks in forked child.
    (bsc#864081, GLIBC BZ #12847)

  - Unlock mutex before going back to waiting for PI
    mutexes. (bsc#891843, GLIBC BZ #14417)

  - Implement x86 cpuid handling of leaf4 for cache
    information. (bsc#903288, GLIBC BZ #12587)

  - Fix infinite loop in check_pf. (bsc#909053, GLIBC BZ
    #12926)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6656.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9402.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10259.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-devel-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-i18ndata-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-locale-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"nscd-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i686", reference:"glibc-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i686", reference:"glibc-devel-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-devel-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-i18ndata-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-locale-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"nscd-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-devel-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-html-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-i18ndata-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-info-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-locale-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-profile-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"nscd-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.80.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.80.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
