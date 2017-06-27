#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0039.
#

include("compat.inc");

if (description)
{
  script_id(97079);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/14 17:23:21 $");

  script_cve_id("CVE-2016-4482", "CVE-2016-4485", "CVE-2016-8630", "CVE-2016-8646", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9576");
  script_osvdb_id(137963, 138086, 146370, 146377, 147015, 147301, 148443);

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2017-0039)");
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

  - vfio/pci: Fix integer overflows, bitmask check (Vlad
    Tsyrklevich) [Orabug: 25164094] (CVE-2016-9083)
    (CVE-2016-9084)

  - Don't feed anything but regular iovec's to
    blk_rq_map_user_iov (Linus Torvalds) [Orabug: 25231931]
    (CVE-2016-9576)

  - kvm: x86: Check memopp before dereference
    (CVE-2016-8630) (Owen Hofmann) [Orabug: 25417387]
    (CVE-2016-8630)

  - crypto: algif_hash - Only export and import on sockets
    with data (Herbert Xu) [Orabug: 25417799]
    (CVE-2016-8646)

  - USB: usbfs: fix potential infoleak in devio (Kangjie Lu)
    [Orabug: 25462755] (CVE-2016-4482)

  - net: fix infoleak in llc (Kangjie Lu) [Orabug: 25462799]
    (CVE-2016-4485)

  - xen-netback: fix extra_info handling in xenvif_tx_err
    (Paul Durrant) [Orabug: 25445336]

  - net: Documentation: Fix default value
    tcp_limit_output_bytes (Niklas Cassel) [Orabug:
    25458076]

  - tcp: double default TSQ output bytes limit (Wei Liu)
    [Orabug: 25458076]

  - xenbus: fix deadlock on writes to /proc/xen/xenbus
    (David Vrabel)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-February/000647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23a1489f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/09");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-61.1.27.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-61.1.27.el6uek")) flag++;

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
