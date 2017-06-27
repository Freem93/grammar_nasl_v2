#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2012-0035.
#

include("compat.inc");

if (description)
{
  script_id(79480);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-3433");
  script_bugtraq_id(54942);

  script_name(english:"OracleVM 3.0 : xen (OVMSA-2012-0035)");
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

  - Xen Security Advisory CVE-2012-3433 / XSA-11 HVM guest
    destroy p2m teardown host DoS vulnerability An HVM guest
    is able to manipulate its physical address space such
    that tearing down the guest takes an extended period
    amount of time searching for shared pages. This causes
    the domain 0 VCPU which tears down the domain to be
    blocked in the destroy hypercall. This causes that
    domain 0 VCPU to become unavailable and may cause the
    domain 0 kernel to panic. There is no requirement for
    memory sharing to be in use. From the patch description:
    xen: only check for shared pages while any exist on
    teardown Avoids worst case behavour when guest has a
    large p2m. This is XSA-11 / CVE-2012-nnn

  - Xen Security Advisory XSA-10 HVM guest user mode MMIO
    emulation DoS vulnerability Internal data of the
    emulator for MMIO operations may, under certain rare
    conditions, at the end of one emulation cycle be left in
    a state affecting a subsequent emulation such that this
    second emulation would fail, causing an exception to be
    reported to the guest kernel where none is expected.
    NOTE: No CVE number! The patch description is as follow:
    x86/hvm: don't leave emulator in inconsistent state The
    fact that handle_mmio, and thus the instruction
    emulator, is being run through twice for emulations that
    require involvement of the device model, allows for the
    second run to see a different guest state than the first
    one. Since only the MMIO-specific emulation routines
    update the vCPU's io_state, if they get invoked on the
    second pass, internal state (and particularly this
    variable) can be left in a state making successful
    emulation of a subsequent MMIO operation impossible.
    Consequently, whenever the emulator invocation returns
    without requesting a retry of the guest instruction,
    reset io_state."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2012-August/000096.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ef1f869"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.0" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.0", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.0", reference:"xen-4.0.0-81.el5.9")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-devel-4.0.0-81.el5.9")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-tools-4.0.0-81.el5.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
