#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2012-0046.
#

include("compat.inc");

if (description)
{
  script_id(79485);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-3515", "CVE-2012-4411");
  script_bugtraq_id(55413, 55442);
  script_osvdb_id(85196);

  script_name(english:"OracleVM 3.1 : xen (OVMSA-2012-0046)");
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

  - Xen Security Advisory CVE-2012-4411 / XSA-19 version 2
    guest administrator can access qemu monitor console
    Disable qemu monitor by default. The qemu monitor is an
    overly powerful feature which must be protected from
    untrusted (guest) administrators. (CVE-2012-4411)

  - fix xm create vcpu_avail exceeds XMLRPC int limits If
    maxvcpus = vcpus = 40, (1<<40 -1) will exceed XMLRPC int
    limit. Change it to str will work. Then in the xend
    side, it will converted back to int. (CVE-2012-3515)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2012-October/000106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdeedcb2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/22");
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
if (rpm_check(release:"OVS3.1", reference:"xen-4.1.2-18.el5.16")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-devel-4.1.2-18.el5.16")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-tools-4.1.2-18.el5.16")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
