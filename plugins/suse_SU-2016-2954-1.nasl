#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2954-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95424);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:18 $");

  script_cve_id("CVE-2016-5011");
  script_osvdb_id(141270);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : util-linux (SUSE-SU-2016:2954-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for util-linux fixes the following issues :

  - Consider redundant slashes when comparing paths
    (bsc#982331,
    util-linux-libmount-ignore-redundant-slashes.patch,
    affects backport of
    util-linux-libmount-cifs-is_mounted.patch).

  - Use upstream compatibility patches for
    --show-pt-geometry with obsolescence and deprecation
    warning (bsc#990531)

  - Replace cifs mount detection patch with upstream one
    that covers all cases (bsc#987176).

  - Reuse existing loop device to prevent possible data
    corruption when multiple -o loop are used to mount a
    single file (bsc#947494)

  - Safe loop re-use in libmount, mount and losetup
    (bsc#947494)

  - UPSTREAM DIVERGENCE!!! losetup -L continues to use SLE12
    SP1 and SP2 specific meaning

    --logical-blocksize instead of upstream --nooverlap
    (bsc#966891).

  - Make release-dependent conflict with old sysvinit-tools
    SLE specific, as it is required only for SLE 11 upgrade,
    and breaks openSUSE staging builds (bsc#994399).

  - Extended partition loop in MBR partition table leads to
    DoS (bsc#988361, CVE-2016-5011)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5011.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162954-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3ea0be1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2016-1729=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2016-1729=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2016-1729=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2016-1729=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2016-1729=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/01");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libblkid1-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libblkid1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfdisk1-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfdisk1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libmount1-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libmount1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsmartcols1-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsmartcols1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libuuid1-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libuuid1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python-libmount-2.28-42.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python-libmount-debuginfo-2.28-42.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python-libmount-debugsource-2.28-42.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"util-linux-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"util-linux-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"util-linux-debugsource-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"util-linux-systemd-2.28-42.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"util-linux-systemd-debuginfo-2.28-42.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"util-linux-systemd-debugsource-2.28-42.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"uuidd-2.28-42.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"uuidd-debuginfo-2.28-42.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libblkid1-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libmount1-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libuuid1-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libblkid1-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libblkid1-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libblkid1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfdisk1-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfdisk1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmount1-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmount1-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmount1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsmartcols1-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsmartcols1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libuuid-devel-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libuuid1-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libuuid1-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libuuid1-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"python-libmount-2.28-42.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"python-libmount-debuginfo-2.28-42.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"python-libmount-debugsource-2.28-42.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"util-linux-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"util-linux-debuginfo-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"util-linux-debugsource-2.28-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"util-linux-systemd-2.28-42.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"util-linux-systemd-debuginfo-2.28-42.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"util-linux-systemd-debugsource-2.28-42.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"uuidd-2.28-42.3")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"uuidd-debuginfo-2.28-42.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}
