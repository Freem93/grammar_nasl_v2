#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2565-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94272);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/28 14:05:24 $");

  script_osvdb_id(145548);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : dbus-1 (SUSE-SU-2016:2565-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dbus-1 to version 1.8.22 fixes one security issue and
bugs. The following security issue was fixed :

  - bsc#1003898: Do not treat ActivationFailure message
    received from root-owned systemd name as a format
    string. The following upstream changes are included :

  - Change the default configuration for the session bus to
    only allow EXTERNAL authentication (secure
    kernel-mediated credentials-passing), as was already
    done for the system bus.

  - Fix a memory leak when GetConnectionCredentials()
    succeeds (fdo#91008)

  - Ensure that dbus-monitor does not reply to messages
    intended for others (fdo#90952)

  - Add locking to DBusCounter's reference count and notify
    function (fdo#89297)

  - Ensure that DBusTransport's reference count is protected
    by the corresponding DBusConnection's lock (fdo#90312)

  - Correctly release DBusServer mutex before early-return
    if we run out of memory while copying authentication
    mechanisms (fdo#90021)

  - Correctly initialize all fields of DBusTypeReader
    (fdo#90021)

  - Fix some missing \n in verbose (debug log) messages
    (fdo#90004)

  - Clean up some memory leaks in test code (fdo#90021)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003898"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162565-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?521ab2a2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1502=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1502=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1502=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dbus-1-x11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdbus-1-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/19");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"dbus-1-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"dbus-1-debuginfo-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"dbus-1-debugsource-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"dbus-1-x11-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"dbus-1-x11-debuginfo-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"dbus-1-x11-debugsource-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdbus-1-3-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdbus-1-3-debuginfo-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"dbus-1-debuginfo-32bit-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdbus-1-3-32bit-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdbus-1-3-debuginfo-32bit-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"dbus-1-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"dbus-1-debuginfo-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"dbus-1-debuginfo-32bit-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"dbus-1-debugsource-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"dbus-1-x11-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"dbus-1-x11-debuginfo-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"dbus-1-x11-debugsource-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdbus-1-3-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-1.8.22-22.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-32bit-1.8.22-22.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1");
}
