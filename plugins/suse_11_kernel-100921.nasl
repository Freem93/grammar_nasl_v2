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
  script_id(51611);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/15 16:41:30 $");

  script_cve_id("CVE-2010-2959", "CVE-2010-3081", "CVE-2010-3301");

  script_name(english:"SuSE 11 Security Update : Linux kernel (SAT Patch Number 3164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update of the SUSE Linux Enterprise 11 GA kernel fixes 3
critical security issues.

Following security bugs were fixed :

  - Mismatch between 32bit and 64bit register usage in the
    system call entry path could be used by local attackers
    to gain root privileges. This problem only affects
    x86_64 kernels. (CVE-2010-3301)

  - Incorrect buffer handling in the biarch-compat buffer
    handling could be used by local attackers to gain root
    privileges. This problem affects foremost x86_64, or
    potentially other biarch platforms, like PowerPC and
    S390x. (CVE-2010-3081)

  - Integer overflow in net/can/bcm.c in the Controller Area
    Network (CAN) implementation in the Linux kernel allowed
    attackers to execute arbitrary code or cause a denial of
    service (system crash) via crafted CAN traffic.
    (CVE-2010-2959)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2959.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3301.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 3164.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-base-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-extra-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-extra-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"ext4dev-kmp-default-0_2.6.27.48_0.12-7.1.40")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.27.48_0.12-7.1.40")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-default-base-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.48-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.48-0.12.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
