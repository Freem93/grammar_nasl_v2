#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0526-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83701);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2013-7423", "CVE-2014-7817", "CVE-2014-9402", "CVE-2015-1472");
  script_bugtraq_id(71216, 71670, 72428, 72498, 72844);
  script_osvdb_id(115032, 116139, 117751, 117873);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : glibc (SUSE-SU-2015:0526-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"glibc has been updated to fix four security issues.

These security issues were fixed :

  - CVE-2014-7817: The wordexp function in GNU C Library
    (aka glibc) 2.21 did not enforce the WRDE_NOCMD flag,
    which allowed context-dependent attackers to execute
    arbitrary commands, as demonstrated by input containing
    '$((`...`))' (bnc#906371).

  - CVE-2015-1472: Heap buffer overflow in glibc swscanf
    (bnc#916222).

  - CVE-2014-9402: Denial of service in getnetbyname
    function (bnc#910599).

  - CVE-2013-7423: Getaddrinfo() writes DNS queries to
    random file descriptors under high load (bnc#915526).

These non-security issues were fixed :

  - Fix infinite loop in check_pf (bsc#909053)

  - Restore warning about execution permission, it is still
    needed for noexec mounts (bsc#915985).

  - Don't touch user-controlled stdio locks in forked child
    (bsc#864081)

  - Don't use gcc extensions for non-gcc compilers
    (bsc#905313)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/906371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916222"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150526-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc89dc81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-129=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-129=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-129=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-debuginfo-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-debugsource-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-debuginfo-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-debuginfo-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-profile-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nscd-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nscd-debuginfo-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-debuginfo-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-debuginfo-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-debuginfo-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-profile-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-debuginfo-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-debugsource-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-debuginfo-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-debuginfo-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"nscd-2.19-20.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"nscd-debuginfo-2.19-20.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
