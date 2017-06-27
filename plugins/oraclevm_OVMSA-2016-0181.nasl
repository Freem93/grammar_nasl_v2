#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0181.
#

include("compat.inc");

if (description)
{
  script_id(96073);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/14 17:23:21 $");

  script_cve_id("CVE-2015-8956", "CVE-2016-1583", "CVE-2016-3070", "CVE-2016-3157", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-6136", "CVE-2016-6480", "CVE-2016-7117", "CVE-2016-9555");
  script_osvdb_id(135947, 138215, 138383, 139987, 140971, 142610, 145048, 145102, 147698);

  script_name(english:"OracleVM 3.2 : Unbreakable / etc (OVMSA-2016-0181)");
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

  - x86/iopl/64: properly context-switch IOPL on Xen PV
    (Andy Lutomirski) [Orabug: 25269184] (CVE-2016-3157)

  - net: Fix use after free in the recvmmsg exit path
    (Arnaldo Carvalho de Melo) [Orabug: 25298618]
    (CVE-2016-7117)

  - logging errors that get masked to EIO inside
    drivers/block/loop.c (Manjunath Patil) [Orabug:
    21962821]

  - sched/core: Clear the root_domain cpumasks in
    init_rootdomain (Xunlei Pang) [Orabug: 23518650]

  - bio allocation failure due to bio_get_nr_vecs (Darrick
    J. Wong) 

  - mlx4: avoid ABBA deadlock (Wengang Wang) [Orabug:
    23538548]

  - mlx4: avoid multiple free on id_map_ent (Wengang Wang)
    [Orabug: 25022815]

  - sctp: validate chunk len before actually using it
    (Marcelo Ricardo Leitner) [Orabug: 25142906]
    (CVE-2016-9555)

  - NVMe: reduce queue depth as workaround for Samsung EPIC
    SQ errata (Ashok Vairavan) [Orabug: 25138146]

  - RDS: Drop the connection as part of cancel to avoid
    hangs (Avinash Repaka) [Orabug: 24951873]

  - aacraid: Check size values after double-fetch from user
    (Dave Carroll) [Orabug: 25060055] (CVE-2016-6480)
    (CVE-2016-6480)

  - audit: fix a double fetch in audit_log_single_execve_arg
    (Paul Moore) [Orabug: 25059962] (CVE-2016-6136)

  - ecryptfs: don't allow mmap when the lower fs doesn't
    support it (Jeff Mahoney) [Orabug: 24971918]
    (CVE-2016-1583) (CVE-2016-1583)

  - ALSA: timer: Fix leak in events via
    snd_timer_user_tinterrupt (Kangjie Lu) [Orabug:
    25059900] (CVE-2016-4578)

  - ALSA: timer: Fix leak in events via
    snd_timer_user_ccallback (Kangjie Lu) [Orabug: 25059900]
    (CVE-2016-4578)

  - ALSA: timer: Fix leak in SNDRV_TIMER_IOCTL_PARAMS
    (Kangjie Lu) [Orabug: 25059755] (CVE-2016-4569)

  - Bluetooth: Fix potential NULL dereference in RFCOMM bind
    callback (Jaganath Kanakkassery) [Orabug: 25058905]
    (CVE-2015-8956)

  - mm: migrate dirty page without clear_page_dirty_for_io
    etc (Hugh Dickins) [Orabug: 25059195] [CVE-2016-3070"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-December/000608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b3f953b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/22");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-400.293.2.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-400.293.2.el5uek")) flag++;

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
