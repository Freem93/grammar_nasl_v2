#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0001.
#

include("compat.inc");

if (description)
{
  script_id(79451);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2008-4405", "CVE-2008-4993");

  script_name(english:"OracleVM 2.1 : xen (OVMSA-2009-0001)");
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

  - Fix permissions problem with VM.GuestMetrics [bugz 7265]

  - Disable
    ovs-disabled-create-netif-if-vif-type-set-ioemu.patch

  - Include proper patch for bugz 7807

  - Implement VM.GuestMetrics to communicate info with guest
    OS [bugz 7265]

  - Support long command line [bugz 7264]

  - Fix bug in valid_object function in XendAPI.py [bugz
    7363]

  - Update MAC address for HVM guest after live migration
    [bugz 7978] [bug 7573550]

  - Fix problem preventing guest from rebooting after
    migration [bugz 7807]

  - Fix guest hang when migrating HVM guests in parallel
    [bugz #7816] 

  - Disable creating backend network device when vif type
    set ioemu [bugz #7592] 

  - pull in cs18449 from xen-3.3-stable 

  - fix invalid reference to XendDomain.VMROOT 

  - Updates from EL5U2 for (CVE-2008-4405, CVE-2008-4993)

  - Fix unsafe use of xenstore data (CVE-2008-4405)

  - Remove qemu-dm.debug wrapper script (CVE-2008-4993)

  - Fix reboots after CVE-2008-4405 changes

  - Fix block-detach regression due to (CVE-2008-4405)

  - make coredump-[destroy|restart] work through traditional
    domU config, back ported from xen unstable cs16989"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-February/000016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5659c439"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-pvhvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/18");
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
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"xen-3.1.4-0.1.29.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"xen-64-3.1.4-0.1.29.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"xen-debugger-3.1.4-0.1.29.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"xen-devel-3.1.4-0.1.29.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"xen-pvhvm-devel-3.1.4-0.1.29.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"xen-tools-3.1.4-0.1.29.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-64 / xen-debugger / xen-devel / xen-pvhvm-devel / etc");
}
