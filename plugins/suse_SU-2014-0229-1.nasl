#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0229-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83610);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2014:0229-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 2 kernel was updated to fix
a regression introduced by the last update.

Regression fix :

  - scsi_dh_alua: Incorrect reference counting in the SCSI
    ALUA initialization code lead to system crashes on boot
    (bnc#858831).

As the update introducing the regression was marked security, this is
also marked security even though this bug is not security relevant.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.novell.com/patch/finder/?keywords=08528bdc933748991934ac0a1ce94e25
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07b0949d"
  );
  # http://download.novell.com/patch/finder/?keywords=10ee063285998a56047341e026dd0951
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?824358c0"
  );
  # http://download.novell.com/patch/finder/?keywords=12b1da540849dcd803c06971282c0173
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c817bead"
  );
  # http://download.novell.com/patch/finder/?keywords=26690338c8e252806b712abfcc1eef01
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1023a984"
  );
  # http://download.novell.com/patch/finder/?keywords=32718e53d0f0b9aa299d1dbf68ba3792
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cececf9d"
  );
  # http://download.novell.com/patch/finder/?keywords=61a5dc8f3780484fe953a849b4c64f03
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec2b0892"
  );
  # http://download.novell.com/patch/finder/?keywords=78531ae4ca3e7e521680f7a48d788159
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e36ea36e"
  );
  # http://download.novell.com/patch/finder/?keywords=9915a8d37fbceb33d8aacbe08afb18a6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?712ff8d0"
  );
  # http://download.novell.com/patch/finder/?keywords=abd5de58f981a6204e3d871981888f09
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?214ce32d"
  );
  # http://download.novell.com/patch/finder/?keywords=d940c974ac1f5b9bad96fada907a460e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f40256da"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858831"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140229-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7796ce20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 for VMware :

zypper in -t patch slessp2-kernel-8865 slessp2-kernel-8868

SUSE Linux Enterprise Server 11 SP2 :

zypper in -t patch slessp2-kernel-8865 slessp2-kernel-8866
slessp2-kernel-8867 slessp2-kernel-8868 slessp2-kernel-8875

SUSE Linux Enterprise High Availability Extension 11 SP2 :

zypper in -t patch sleshasp2-kernel-8865 sleshasp2-kernel-8866
sleshasp2-kernel-8867 sleshasp2-kernel-8868 sleshasp2-kernel-8875

SUSE Linux Enterprise Desktop 11 SP2 :

zypper in -t patch sledsp2-kernel-8865 sledsp2-kernel-8868

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/12");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-source-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-syms-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-source-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-syms-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.7.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_04_3.0.101_0.7.17-0.5.16")) flag++;


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
