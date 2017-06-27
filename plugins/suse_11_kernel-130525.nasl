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
  script_id(66742);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2013-2850");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 7763 / 7766 / 7767)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel has been updated to fix a
critical security issue.

  - Incorrect strncpy usage in the network listening part of
    the iscsi target driver could have been used by remote
    attackers to crash the kernel or execute code.
    (CVE-2013-2850)

    This required the iscsi target running on the machine
    and the attacker able to make a network connection to it
    (aka not filtered by firewalls)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2850.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 7763 / 7766 / 7767 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/02");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.4_02_3.0.74_0.6.10-0.5.32")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.4_02_3.0.74_0.6.10-0.5.32")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.74-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.4_02_3.0.74_0.6.10-0.5.32")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.4_02_3.0.74_0.6.10-0.5.32")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
