#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1346-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91253);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2014-9770", "CVE-2015-8842");
  script_osvdb_id(137177, 137885);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : systemd (SUSE-SU-2016:1346-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for SystemD provides fixes and enhancements.

The following security issue has been fixed :

  - Don't allow read access to journal files to users.
    (bsc#972612, CVE-2014-9770, CVE-2015-8842)

The following non-security issues have been fixed :

  - Restore initrd-udevadm-cleanup-db.service. (bsc#978275,
    bsc#976766)

  - Incorrect permissions set after boot on journal files.
    (bsc#973848)

  - Exclude device-mapper from block device ownership event
    locking. (bsc#972727)

  - Explicitly set mode for /run/log.

  - Don't apply sgid and executable bit to journal files,
    only the directories they are contained in.

  - Add ability to mask access mode by pre-existing access
    mode on files/directories.

  - No need to pass --all if inactive is explicitly
    requested in list-units. (bsc#967122)

  - Fix automount option and don't start associated mount
    unit at boot. (bsc#970423)

  - Support more than just power-gpio-key. (fate#318444,
    bsc#970860)

  - Add standard gpio power button support. (fate#318444,
    bsc#970860)

  - Downgrade warnings about wanted unit which are not
    found. (bsc#960158)

  - Shorten hostname before checking for trailing dot.
    (bsc#965897)

  - Remove WorkingDirectory parameter from emergency, rescue
    and console-shell.service. (bsc#959886)

  - Don't ship boot.udev and systemd-journald.init anymore.

  - Revert 'log: honour the kernel's quiet cmdline
    argument'. (bsc#963230)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9770.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8842.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161346-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?681897b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-790=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-790=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-790=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-debuginfo-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-debuginfo-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-debuginfo-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-debugsource-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-sysvinit-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"udev-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"udev-debuginfo-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-debuginfo-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-debuginfo-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-debuginfo-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-debuginfo-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-debuginfo-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-debuginfo-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-debuginfo-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-debuginfo-32bit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-debugsource-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-sysvinit-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"udev-210-104.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"udev-debuginfo-210-104.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
