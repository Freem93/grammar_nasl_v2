#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0033.
#

include("compat.inc");

if (description)
{
  script_id(79470);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2009-2695", "CVE-2009-2849", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3613");
  script_bugtraq_id(36304, 36472, 36706, 36901);
  script_osvdb_id(59654);

  script_name(english:"OracleVM 2.2 : kernel (OVMSA-2009-0033)");
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

  - [security] require root for mmap_min_addr (Eric Paris)
    [518142 518143] (CVE-2009-2695)

  - [md] prevent crash when accessing suspend_* sysfs attr
    (Danny Feng) [518135 518136] (CVE-2009-2849)

  - [nfs] knfsd: fix NFSv4 O_EXCL creates (Jeff Layton)
    [522163 524521] (CVE-2009-3286)

  - [fs] fix pipe null pointer dereference (Jeff Moyer)
    [530938 530939] (CVE-2009-3547)

  - [net] r8169: balance pci_map/unmap pair, use hw padding
    (Ivan Vecera) [529143 515857] (CVE-2009-3613)

  - [net] tc: fix uninitialized kernel memory leak (Jiri
    Pirko) [520994 520863](CVE-2009-3228)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-November/000039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6f5df51"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/16");
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
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"kernel-2.6.18-128.2.1.4.12.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-devel-2.6.18-128.2.1.4.12.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-ovs-2.6.18-128.2.1.4.12.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-ovs-devel-2.6.18-128.2.1.4.12.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-ovs / kernel-ovs-devel");
}
