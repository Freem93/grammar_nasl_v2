#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1151-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83590);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2013:1151-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 2 kernel was respun with the
3.0.80 update to fix a severe compatibility problem with kernel module
packages (KMPs) like e.g. drbd.

An incompatible ABI change could lead to those modules not correctly
working or crashing on loading and is fixed by this update.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=2933fc1d318570fd29fc9c882118e2f9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7a432d5"
  );
  # http://download.suse.com/patch/finder/?keywords=3979393609bc7fc0060c84d8f6c614c9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bd79f29"
  );
  # http://download.suse.com/patch/finder/?keywords=42ff2be8ec2fb21f7d494600848c4ad6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edbbfdd7"
  );
  # http://download.suse.com/patch/finder/?keywords=511f063f92e4fd065bc4f18cd512dd97
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fe2c8ad"
  );
  # http://download.suse.com/patch/finder/?keywords=75d8104813f10db3bb35f4b6cf167e3b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fab803bf"
  );
  # http://download.suse.com/patch/finder/?keywords=8e023846e9b2123c71d7008b4f22b419
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64f2241a"
  );
  # http://download.suse.com/patch/finder/?keywords=94d76106e50952487c5aea15fedb7f6b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8ad8a41"
  );
  # http://download.suse.com/patch/finder/?keywords=af79d110bc75684f84ac6baab338862e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9eedb8c0"
  );
  # http://download.suse.com/patch/finder/?keywords=b60e1d289121ae78ca5a36000a3bcd58
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89f44da0"
  );
  # http://download.suse.com/patch/finder/?keywords=f868176ad335455918aedbb9666e1a3c
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a194b92"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/825657"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131151-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6384fa75"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 for VMware :

zypper in -t patch slessp2-kernel-7954 slessp2-kernel-7960

SUSE Linux Enterprise Server 11 SP2 :

zypper in -t patch slessp2-kernel-7954 slessp2-kernel-7957
slessp2-kernel-7958 slessp2-kernel-7959 slessp2-kernel-7960

SUSE Linux Enterprise High Availability Extension 11 SP2 :

zypper in -t patch sleshasp2-kernel-7954 sleshasp2-kernel-7957
sleshasp2-kernel-7958 sleshasp2-kernel-7959 sleshasp2-kernel-7960

SUSE Linux Enterprise Desktop 11 SP2 :

zypper in -t patch sledsp2-kernel-7954 sledsp2-kernel-7960

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/05");
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
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.80_0.7-0.5.18")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.80_0.7-0.5.18")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-source-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-syms-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-trace-extra-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-xen-extra-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.80_0.7-0.5.18")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.80_0.7-0.5.18")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"kernel-pae-extra-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-default-extra-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-source-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-syms-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-trace-extra-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-xen-extra-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.80-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"kernel-pae-extra-3.0.80-0.7.1")) flag++;


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
