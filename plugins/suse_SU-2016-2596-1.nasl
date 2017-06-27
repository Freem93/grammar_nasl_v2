#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2596-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94280);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/16 16:05:34 $");

  script_cve_id("CVE-2016-5195");
  script_osvdb_id(146061);
  script_xref(name:"IAVA", value:"2016-A-0306");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2016:2596-1) (Dirty COW)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 LTSS kernel was updated to fix one
security issue. This security bug was fixed :

  - CVE-2016-5195: Local privilege escalation using
    MAP_PRIVATE. It is reportedly exploited in the wild
    (bsc#1004418).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5195.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162596-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dacd1003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-kernel-source-12807=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-kernel-source-12807=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.44.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
