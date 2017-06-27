#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0101.
#

include("compat.inc");

if (description)
{
  script_id(100115);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2016-9603", "CVE-2017-2633", "CVE-2017-7718", "CVE-2017-7980");
  script_osvdb_id(152424, 153753, 155921, 156069);

  script_name(english:"OracleVM 3.4 : qemu-kvm (OVMSA-2017-0101)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - kvm-cirrus-avoid-write-only-variables.patch [bz#1444377
    bz#1444379]

  -
    kvm-cirrus-stop-passing-around-dst-pointers-in-the-blitt
    .patch 

  -
    kvm-cirrus-stop-passing-around-src-pointers-in-the-blitt
    .patch 

  -
    kvm-cirrus-fix-off-by-one-in-cirrus_bitblt_rop_bkwd_tran
    .patch 

  - kvm-cirrus-fix-PUTPIXEL-macro.patch [bz#1444377
    bz#1444379]

  - Resolves: bz#1444377 (CVE-2017-7980 qemu-kvm: Qemu:
    display: cirrus: OOB r/w access issues in bitblt
    routines [rhel-6.9.z])

  - Resolves: bz#1444379 (CVE-2017-7980 qemu-kvm-rhev: Qemu:
    display: cirrus: OOB r/w access issues in bitblt
    routines [rhel-6.9.z])

  -
    kvm-fix-cirrus_vga-fix-OOB-read-case-qemu-Segmentation-f
    .patch 

  -
    kvm-cirrus-vnc-zap-bitblit-support-from-console-code.pat
    ch [bz#1443447 bz#1443449]

  - Resolves: bz#1443447 (CVE-2017-7718 qemu-kvm: Qemu:
    display: cirrus: OOB read access issue [rhel-6.9.z])

  - Resolves: bz#1443449 (CVE-2017-7718 qemu-kvm-rhev: Qemu:
    display: cirrus: OOB read access issue [rhel-6.9.z])

  - Resolves: bz#1447544 (CVE-2016-9603 qemu-kvm-rhev: Qemu:
    cirrus: heap buffer overflow via vnc connection
    [rhel-6.9.z])

  - Resolves: bz#1447540 (CVE-2016-9603 qemu-kvm: Qemu:
    cirrus: heap buffer overflow via vnc connection
    [rhel-6.9.z])

  - kvm-vns-tls-don-t-use-depricated-gnutls-functions.patch
    [bz#1428750]

  - kvm-vnc-apply-display-size-limits.patch [bz#1400438
    bz#1425943]

  - Resolves: bz#1400438 (qemu-kvm coredump in
    vnc_refresh_server_surface [rhel-6.9.z])

  - Resolves: bz#1425943 (CVE-2017-2633 qemu-kvm-rhev: Qemu:
    VNC: memory corruption due to unchecked resolution limit
    [rhel-6.9.z])

  - Resolves: bz#1428750 (Fails to build in brew)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000694.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-img package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");
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
if (rpm_check(release:"OVS3.4", reference:"qemu-img-0.12.1.2-2.503.el6_9.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img");
}
