#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:0454 and 
# Oracle Linux Security Advisory ELSA-2017-0454 respectively.
#

include("compat.inc");

if (description)
{
  script_id(97593);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/10 16:46:29 $");

  script_cve_id("CVE-2017-2615", "CVE-2017-2620");
  script_osvdb_id(151241, 152349);
  script_xref(name:"RHSA", value:"2017:0454");
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"Oracle Linux 5 : kvm (ELSA-2017-0454)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:0454 :

An update for kvm is now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

KVM (for Kernel-based Virtual Machine) is a full virtualization
solution for Linux on x86 hardware. Using KVM, one can run multiple
virtual machines running unmodified Linux or Windows images. Each
virtual machine has private virtualized hardware: a network card,
disk, graphics adapter, etc.

Security Fix(es) :

* Quick emulator (QEMU) built with the Cirrus CLGD 54xx VGA emulator
support is vulnerable to an out-of-bounds access issue. It could occur
while copying VGA data via bitblt copy in backward mode. A privileged
user inside a guest could use this flaw to crash the QEMU process
resulting in DoS or potentially execute arbitrary code on the host
with privileges of QEMU process on the host. (CVE-2017-2615)

* Quick emulator (QEMU) built with the Cirrus CLGD 54xx VGA Emulator
support is vulnerable to an out-of-bounds access issue. The issue
could occur while copying VGA data in cirrus_bitblt_cputovideo. A
privileged user inside guest could use this flaw to crash the QEMU
process OR potentially execute arbitrary code on host with privileges
of the QEMU process. (CVE-2017-2620)

Red Hat would like to thank Wjjzhang (Tencent.com Inc.) and Li Qiang
(360.cn Inc.) for reporting CVE-2017-2615."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-March/006773.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmod-kvm-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kmod-kvm-83-277.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kmod-kvm-debug-83-277.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-83-277.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-qemu-img-83-277.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-tools-83-277.0.1.el5_11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kmod-kvm-debug / kvm / kvm-qemu-img / kvm-tools");
}
