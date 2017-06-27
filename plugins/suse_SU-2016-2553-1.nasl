#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2553-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94271);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/03 13:47:03 $");

  script_cve_id("CVE-2016-5759");
  script_osvdb_id(146504);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kdump (SUSE-SU-2016:2553-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kdump provides several fixes and enhancements :

  - Refresh kdumprd if /etc/hosts or /etc/nsswitch.conf is
    changed. (bsc#943214)

  - Add a separate systemd service to rebuild kdumprd at
    boot. (bsc#943214)

  - Improve network setup in the kdump environment by
    reading configuration from wicked by default (system
    configuration files are used as a fallback).
    (bsc#980328)

  - Use the last mount entry in kdump_get_mountpoints().
    (bsc#951844)

  - Remove 'notsc' from the kdump kernel command line.
    (bsc#973213)

  - Handle dump files with many program headers.
    (bsc#932339, bsc#970708)

  - Fall back to stat() if file type is DT_UNKNOWN.
    (bsc#964206)

  - Remove vm. sysctls from kdump initrd. (bsc#927451,
    bsc#987862)

  - Use the exit code of kexec, not that of 'local'.
    (bsc#984799)

  - Convert sysroot to a bind mount in kdump initrd.
    (bsc#976864)

  - Distinguish between Xenlinux (aka Xenified or SUSE) and
    pvops Xen kernels, as the latter can run on bare metal.
    (bsc#974270)

  - CVE-2016-5759: Use full path to dracut as argument to
    bash. (bsc#989972, bsc#990200)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5759.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162553-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ac61c6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1492=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1492=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"kdump-0.8.15-29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kdump-debuginfo-0.8.15-29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kdump-debugsource-0.8.15-29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kdump-0.8.15-29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kdump-debuginfo-0.8.15-29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kdump-debugsource-0.8.15-29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdump");
}
