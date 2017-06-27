#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0062.
#

include("compat.inc");

if (description)
{
  script_id(99392);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/14 18:41:29 $");

  script_cve_id("CVE-2016-10208", "CVE-2016-7910", "CVE-2017-2583", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6347", "CVE-2017-7184");
  script_osvdb_id(147034, 147763, 150690, 152094, 152453, 152704, 153853);

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2017-0062)");
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

  - uek-rpm: enable CONFIG_KSPLICE. (Jamie Iles) [Orabug:
    25698171]

  - ksplice: add sysctls for determining Ksplice features.
    (Jamie Iles) 

  - signal: protect SIGNAL_UNKILLABLE from unintentional
    clearing. (Jamie Iles) [Orabug: 25698171]

  - KVM: x86: fix emulation of 'MOV SS, null selector'
    (Paolo Bonzini) [Orabug: 25719659] (CVE-2017-2583)
    (CVE-2017-2583)

  - ext4: store checksum seed in superblock (Darrick J.
    Wong) [Orabug: 25719728] (CVE-2016-10208)

  - ext4: reserve code points for the project quota feature
    (Theodore Ts'o) [Orabug: 25719728] (CVE-2016-10208)

  - ext4: validate s_first_meta_bg at mount time (Eryu Guan)
    [Orabug: 25719728] (CVE-2016-10208)

  - ext4: clean up feature test macros with predicate
    functions (Darrick J. Wong) [Orabug: 25719728]
    (CVE-2016-10208)

  - sctp: avoid BUG_ON on sctp_wait_for_sndbuf (Marcelo
    Ricardo Leitner) [Orabug: 25719793] (CVE-2017-5986)

  - tcp: avoid infinite loop in tcp_splice_read (Eric
    Dumazet) [Orabug: 25720805] (CVE-2017-6214)

  - ip: fix IP_CHECKSUM handling (Paolo Abeni) [Orabug:
    25720839] (CVE-2017-6347)

  - udp: fix IP_CHECKSUM handling (Eric Dumazet) [Orabug:
    25720839] (CVE-2017-6347)

  - udp: do not expect udp headers in recv cmsg
    IP_CMSG_CHECKSUM (Willem de Bruijn) [Orabug: 25720839]
    (CVE-2017-6347)

  - xfrm_user: validate XFRM_MSG_NEWAE incoming ESN size
    harder (Andy Whitcroft) [Orabug: 25814641]
    (CVE-2017-7184)

  - xfrm_user: validate XFRM_MSG_NEWAE XFRMA_REPLAY_ESN_VAL
    replay_window (Andy Whitcroft) [Orabug: 25814641]
    (CVE-2017-7184)

  - block: fix use-after-free in seq file (Vegard Nossum)
    [Orabug: 25877509] (CVE-2016-7910)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-April/000678.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d24288bf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-61.1.34.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-61.1.34.el6uek")) flag++;

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
