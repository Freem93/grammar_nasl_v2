#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0060.
#

include("compat.inc");

if (description)
{
  script_id(91743);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2013-4312", "CVE-2015-7509", "CVE-2015-8215", "CVE-2015-8543", "CVE-2015-8767", "CVE-2016-4565");
  script_osvdb_id(127518, 131685, 132202, 132811, 133379, 138176);

  script_name(english:"OracleVM 3.2 : kernel-uek (OVMSA-2016-0060)");
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

  - IPoIB: increase send queue size to 4 times (Ajaykumar
    Hotchandani) 

  - IB/ipoib: Change send workqueue size for CM mode
    (Ajaykumar Hotchandani) [Orabug: 22287489]

  - Avoid 60sec timeout when receiving rtpg sense code
    06/00/00 (John Sobecki) [Orabug: 22336257]

  - stop recursive fault in print_context_stack after stack
    overflow (John Sobecki) [Orabug: 23174777]

  - IB/security: Restrict use of the write interface (Jason
    Gunthorpe) [Orabug: 23287131] (CVE-2016-4565)

  - net: add validation for the socket syscall protocol
    argument (Hannes Frederic Sowa) [Orabug: 23267976]
    (CVE-2015-8543) (CVE-2015-8543)

  - ipv6: addrconf: validate new MTU before applying it
    (Marcelo Leitner) [Orabug: 23263251] (CVE-2015-8215)

  - ext4: avoid hang when mounting non-journal filesystems
    with orphan list (Theodore Ts'o) [Orabug: 23262219]
    (CVE-2015-7509)

  - ext4: make orphan functions be no-op in no-journal mode
    (Anatol Pomozov) [Orabug: 23262219] (CVE-2015-7509)

  - unix: properly account for FDs passed over unix sockets
    (willy tarreau) [Orabug: 23262265] (CVE-2013-4312)
    (CVE-2013-4312)

  - sctp: Prevent soft lockup when sctp_accept is called
    during a timeout event (Karl Heiss) [Orabug: 23222773]
    (CVE-2015-8767)

  - [SUNRPC]: avoid race between xs_reset_transport and
    xs_tcp_setup_socket (Wengang Wang)

  - x86_64: expand kernel stack to 16K (Minchan Kim)
    [Orabug: 20920074]

  - qla2xxx: fix wrongly report 'PCI EEH busy' when
    get_thermal_temp (Vaughan Cao) [Orabug: 21108318]

  - RDS/IB: VRPC DELAY / OSS RECONNECT CAUSES 5 MINUTE STALL
    ON PORT FAILURE (Venkat Venkatsubra) [Orabug: 21465077]

  - RDS: Fix the atomicity for congestion map update
    (Wengang Wang) 

  - RDS: introduce generic [clear,set]_bit_le (Wengang Wang)
    [Orabug: 22118109]

  - cifs: allow socket to clear and app threads to set
    tcpStatus CifsNeedReconnect (John Sobecki) [Orabug:
    22203554]

  - mlx4_vnic: Enable LRO for mlx4_vnic net devices. (Ashish
    Samant) 

  - mlx4_vnic: Add correct typecasting to pointers. (Ashish
    Samant) 

  - veth: don&rsquo t modify ip_summed  doing so treats
    packets with bad checksums as good. (Vijay Pandurangan)
    [Orabug: 22804574]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000481.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
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
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-400.279.1.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-400.279.1.el5uek")) flag++;

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
