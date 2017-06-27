#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1908-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86756);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2014-0222", "CVE-2015-4037", "CVE-2015-5239", "CVE-2015-6815", "CVE-2015-7311", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7971");
  script_bugtraq_id(67357, 74809);
  script_osvdb_id(106983, 122500, 127119, 127150, 128019, 129597, 129598, 129600);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2015:1908-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xen was updated to version 4.4.3 to fix nine security issues.

These security issues were fixed :

  - CVE-2015-4037: The slirp_smb function in net/slirp.c
    created temporary files with predictable names, which
    allowed local users to cause a denial of service
    (instantiation failure) by creating /tmp/qemu-smb.*-*
    files before the program (bsc#932267).

  - CVE-2014-0222: Integer overflow in the qcow_open
    function allowed remote attackers to cause a denial of
    service (crash) via a large L2 table in a QCOW version 1
    image (bsc#877642).

  - CVE-2015-7835: Uncontrolled creation of large page
    mappings by PV guests (bsc#950367).

  - CVE-2015-7311: libxl in Xen did not properly handle the
    readonly flag on disks when using the qemu-xen device
    model, which allowed local guest users to write to a
    read-only disk image (bsc#947165).

  - CVE-2015-5239: Integer overflow in vnc_client_read() and
    protocol_client_msg() (bsc#944463).

  - CVE-2015-6815: With e1000 NIC emulation support it was
    possible to enter an infinite loop (bsc#944697).

  - CVE-2015-7969: Leak of main per-domain vcpu pointer
    array leading to denial of service (bsc#950703).

  - CVE-2015-7969: Leak of per-domain profiling- related
    vcpu pointer array leading to denial of service
    (bsc#950705).

  - CVE-2015-7971: Some pmu and profiling hypercalls log
    without rate limiting (bsc#950706).

These non-security issues were fixed :

  - bsc#907514: Bus fatal error: SLES 12 sudden reboot has
    been observed

  - bsc#910258: SLES12 Xen host crashes with FATAL NMI after
    shutdown of guest with VT-d NIC

  - bsc#918984: Bus fatal error: SLES11-SP4 sudden reboot
    has been observed

  - bsc#923967: Partner-L3: Bus fatal error: SLES11-SP3
    sudden reboot has been observed

  - bnc#901488: Intel ixgbe driver assigns rx/tx queues per
    core resulting in irq problems on servers with a large
    amount of CPU cores

  - bsc#945167: Running command: xl pci-assignable-add
    03:10.1 secondly show errors

  - bsc#949138: Setting vcpu affinity under Xen causes
    libvirtd abort

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/877642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0222.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5239.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7969.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7971.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151908-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ae68ee8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-795=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-795=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-795=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.3_02_k3.12.48_52.27-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.3_02_k3.12.48_52.27-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.3_02_k3.12.48_52.27-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.3_02_k3.12.48_52.27-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.3_02-22.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.3_02-22.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
