#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2012:1708-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83571);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2011-0695", "CVE-2012-3430");
  script_bugtraq_id(46839, 54702);

  script_name(english:"SUSE SLES10 Security Update : ofed (SUSE-SU-2012:1708-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ofed fixed multiple issues (including security related
flaws) :

  - sdp: move histogram allocation from stack to heap
    (bnc#706175)

  - cma: Fix crash in request handlers (bnc#678795,
    CVE-2011-0695)

  - rds: set correct msg_namelen (bnc#773383, CVE-2012-3430)

  - cm: Bump reference count on cm_id before invoking
    (bnc#678795, CVE-2011-0695)

  - sdp / ipath: Added fixes for 64bit divide on 32bit
    builds

  - updated Infiniband sysconfig file to match openibd
    (bnc#721597)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=e928539d6bca959aca91d810ff33a425
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ca7d717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/676724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/678795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/706175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/721597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773383"
  );
  # https://www.suse.com/support/update/announcement/2012/suse-su-20121708-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00f9d7b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ofed packages");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-cxgb3-NIC-kmp-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-vmipae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-1.5.2-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-default-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-doc-1.5.2-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-default-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-debug-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-debug-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-kdump-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-kdump-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-smp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-smp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-bigsmp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-kdumppae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-vmi-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-cxgb3-NIC-kmp-vmipae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-bigsmp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-kdumppae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-vmi-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ofed-kmp-vmipae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-1.5.2-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-default-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-doc-1.5.2-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-default-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-debug-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-debug-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-kdump-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-kdump-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-smp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-smp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-bigsmp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-kdumppae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-vmi-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-cxgb3-NIC-kmp-vmipae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-bigsmp-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-kdumppae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-vmi-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ofed-kmp-vmipae-1.5.2_2.6.16.60_0.99.13-0.12.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ofed");
}
