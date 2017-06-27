#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0004.
#

include("compat.inc");

if (description)
{
  script_id(96517);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/14 17:23:21 $");

  script_cve_id("CVE-2016-6828", "CVE-2016-7042", "CVE-2016-8655", "CVE-2016-8666", "CVE-2016-9793", "CVE-2016-9794", "CVE-2016-9806");
  script_osvdb_id(142992, 145585, 145649, 145694, 148137, 148164, 148388, 148409);

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2017-0004)");
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

  - KEYS: Fix short sprintf buffer in /proc/keys show
    function (David Howells) [Orabug: 25306361]
    (CVE-2016-7042)

  - nvme: Limit command retries (Keith Busch) [Orabug:
    25374751]

  - fs/proc/task_mmu.c: fix mm_access mode parameter in
    pagemap_read (Kenny Keslar) [Orabug: 25374977]

  - tcp: fix use after free in tcp_xmit_retransmit_queue
    (Eric Dumazet) [Orabug: 25374364] (CVE-2016-6828)

  - tunnels: Don't apply GRO to multiple layers of
    encapsulation. (Jesse Gross) [Orabug: 25036352]
    (CVE-2016-8666)

  - i40e: Don't notify client(s) for DCB changes on all VSIs
    (Neerav Parikh) [Orabug: 25046290]

  - packet: fix race condition in packet_set_ring (Philip
    Pettersson) [Orabug: 25231617] (CVE-2016-8655)

  - netlink: Fix dump skb leak/double free (Herbert Xu)
    [Orabug: 25231692] (CVE-2016-9806)

  - ALSA: pcm : Call kill_fasync in stream lock (Takashi
    Iwai) [Orabug: 25231720] (CVE-2016-9794)

  - net: avoid signed overflows for SO_[SND|RCV]BUFFORCE
    (Eric Dumazet) [Orabug: 25231751] (CVE-2016-9793)

  - rebuild bumping release"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-January/000615.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba5d5274"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-61.1.25.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-61.1.25.el6uek")) flag++;

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
