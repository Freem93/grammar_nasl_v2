#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2476-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93937);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:10 $");

  script_cve_id("CVE-2016-7796");
  script_osvdb_id(144920);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : systemd (SUSE-SU-2016:2476-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following security issue :

  - CVE-2016-7796: A zero-length message received over
    systemd's notification socket could make
    manager_dispatch_notify_fd() return an error and, as a
    side effect, disable the notification handler
    completely. As the notification socket is
    world-writable, this could have allowed a local user to
    perform a denial-of-service attack against systemd.
    (bsc#1001765) Additionally, the following non-security
    fixes are included :

  - Fix HMAC calculation when appending a data object to
    journal. (bsc#1000435)

  - Never accept file descriptors from file systems with
    mandatory locking enabled. (bsc#954374)

  - Do not warn about missing install info with 'preset'.
    (bsc#970293)

  - Save /run/systemd/users/UID before starting
    user@.service. (bsc#996269)

  - Make sure that /var/lib/systemd/sysv-convert/database is
    always initialized. (bsc#982211)

  - Remove daylight saving time handling and tzfile parser.
    (bsc#990074)

  - Make sure directory watch is started before cryptsetup.
    (bsc#987173)

  - Introduce sd_pid_notify() and sd_pid_notifyf() APIs.
    (bsc#987857)

  - Set KillMode=mixed for our daemons that fork worker
    processes.

  - Add nosuid and nodev options to tmp.mount.

  - Don't start console-getty.service when /dev/console is
    missing. (bsc#982251)

  - Correct segmentation fault in udev/path_id due to
    missing NULL check. (bsc#982210)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/996269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7796.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162476-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2064e22e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1448=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1448=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1448=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/10");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-debuginfo-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-debuginfo-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-debuginfo-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-debugsource-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-sysvinit-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"udev-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"udev-debuginfo-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgudev-1_0-0-debuginfo-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libudev1-debuginfo-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"systemd-debuginfo-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-debuginfo-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgudev-1_0-0-debuginfo-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-debuginfo-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-debuginfo-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-debuginfo-32bit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-debugsource-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"systemd-sysvinit-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"udev-210-114.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"udev-debuginfo-210-114.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
