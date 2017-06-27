#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0032.
#

include("compat.inc");

if (description)
{
  script_id(79503);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-1917", "CVE-2013-1919", "CVE-2013-1920");
  script_bugtraq_id(58880, 59291, 59292);

  script_name(english:"OracleVM 3.1 : xen (OVMSA-2013-0032)");
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

  - defer event channel bucket pointer store until after XSM
    checks Otherwise a dangling pointer can be left, which
    would cause subsequent memory corruption as soon as the
    space got re-allocated for some other purpose. This is
    CVE-2013-1920 / XSA-47.

  - x86: fix various issues with handling guest IRQs

  - properly revoke IRQ access in map_domain_pirq error path

  - don't permit replacing an in use IRQ

  - don't accept inputs in the GSI range for
    MAP_PIRQ_TYPE_MSI

  - track IRQ access permission in host IRQ terms, not guest
    IRQ ones (and with that, also disallow Dom0 access to
    IRQ0) This is CVE-2013-1919 / XSA-46.

  - x86: clear EFLAGS.NT in SYSENTER entry path ... as it
    causes problems if we happen to exit back via IRET: In
    the course of trying to handle the fault, the hypervisor
    creates a stack course of trying to handle the fault,
    the hypervisor creates a stack frame by hand, and uses
    PUSHFQ to set the respective EFLAGS field, but expects
    to be able to IRET through that stack frame to the
    second portion of the fixup code (which causes a #GP due
    to the stored EFLAGS having NT set). And even if this
    worked (e.g if we cleared NT in that path), it would
    then (through the fail safe callback) cause a #GP in the
    guest with the SYSENTER handler's first instruction as
    the source, which in turn would allow guest user mode
    code to crash the guest kernel. Inject a #GP on the fake
    (NULL) address of the SYSENTER instruction instead, just
    like in the case where the guest kernel didn't register
    a corresponding entry point. On 32-bit we also need to
    make sure we clear SYSENTER_CS for all CPUs (neither
    #RESET nor #INIT guarantee this). This is CVE-2013-1917
    / XSA-44. (CVE-2013-1917)

  - Current Xend allowing multiple call destroy for the same
    domain, this lead multiple hard resets(FLR) for pci
    pass-through, and some controller might failed. In our
    test, we pass through 2 LSI HAB controllers to the PVHVM
    guest, after guest brought up, call xm-destroy twice,
    the adapters's BIOS will hung, and we had to reboot the
    server to recovery it. BTW: I had send this patch to Xen
    maillist, but developer said Xend will obsolete and
    would not review and merge the fix."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-April/000142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?316f37b9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/22");
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
if (! ereg(pattern:"^OVS" + "3\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.1", reference:"xen-4.1.2-18.el5.41")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-devel-4.1.2-18.el5.41")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-tools-4.1.2-18.el5.41")) flag++;

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
