#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0163.
#

include("compat.inc");

if (description)
{
  script_id(95046);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2015-8956", "CVE-2016-2053", "CVE-2016-3070", "CVE-2016-3699", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-6136", "CVE-2016-6327", "CVE-2016-6480");
  script_osvdb_id(133550, 138215, 138383, 140971, 142610, 143247, 144731, 145102);

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2016-0163)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - aacraid: Check size values after double-fetch from user
    (Dave Carroll) [Orabug: 25060050] (CVE-2016-6480)
    (CVE-2016-6480)

  - IB/srpt: Simplify srpt_handle_tsk_mgmt (Bart Van Assche)
    [Orabug: 25060011] (CVE-2016-6327)

  - audit: fix a double fetch in audit_log_single_execve_arg
    (Paul Moore) [Orabug: 25059945] (CVE-2016-6136)

  - ALSA: timer: Fix leak in events via
    snd_timer_user_tinterrupt (Kangjie Lu) [Orabug:
    25059899] (CVE-2016-4578)

  - ALSA: timer: Fix leak in events via
    snd_timer_user_ccallback (Kangjie Lu) [Orabug: 25059899]
    (CVE-2016-4578)

  - ALSA: timer: Fix leak in SNDRV_TIMER_IOCTL_PARAMS
    (Kangjie Lu) [Orabug: 25059753] (CVE-2016-4569)

  - acpi: Disable ACPI table override if securelevel is set
    (Linn Crosetto) [Orabug: 25058991] (CVE-2016-3699)

  - Bluetooth: Fix potential NULL dereference in RFCOMM bind
    callback (Jaganath Kanakkassery) [Orabug: 25058903]
    (CVE-2015-8956)

  - ASN.1: Fix non-match detection failure on data overrun
    (David Howells) [Orabug: 25059046] (CVE-2016-2053)

  - mm: migrate dirty page without clear_page_dirty_for_io
    etc (Hugh Dickins) [Orabug: 25059194] (CVE-2016-3070)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-November/000588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8247686e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.14.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.14.2.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
