#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2012-0020.
#

include("compat.inc");

if (description)
{
  script_id(79476);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2006-0744", "CVE-2012-0217");
  script_bugtraq_id(53856);
  script_osvdb_id(82850);

  script_name(english:"OracleVM 3.0 : xen (OVMSA-2012-0020)");
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

  - x86-64: detect processors subject to AMD erratum #121
    and refuse to boot(CVE-2006-0744)

  - guest denial of service on syscall/sysenter exception
    generation (CVE-2012-0217)

  - Remove unnecessary balloon retries on vm create. This is
    a backport from fix for bug 14143327.

  - This backport from 3.1.1: Author: amisherf Put back the
    patch that prevent older guest that uses kudzu from
    hanging on a reboot. Fixed the patch to prevent
    excessive watcher writes which causes xend, xenstored to
    run at a 100% cpu usage. Now the watch is written only
    if console in Initialising, InitWait, Initialised states
    which happen once at boot time. [bug 13523487]

  - Backport from upstream changeset 20968 xend: notify
    xenpv device model that console info is ready Sometimes
    PV domain with vfb doesn't boot up. /sbin/kudzu is
    stuck. After investigation, I've found that the evtchn
    for console is not bound at all. Normal sequence of
    evtchn initialization in qemu-dm for xenpv is: 1) watch
    xenstore backpath
    (/local/domain/0/backend/console/<domid>/0) 2) read
    console info (/local/domain/<domid>/console/[type,
    ring-ref, port..= ]) 3) bind the evtchn to the port. But
    in some case, xend writes to the backpath before the
    console info is prepared, and never write to the
    backpath again. So the qemu-dm fails at 2) and never
    reach to 3). When this happens, manually xenstore-write
    command on Domain-0 resumes the guest.

  - Set max cstate to 1. This is a backport requirement for
    bug 13703504. We have several bugs that cstate made
    system unstable, both for ovm2 and ovm3: For OVM3.x: Bug
    13703504 - unexplained network disconnect causes ocfs to
    fence the server For OVM2.x"
  );
  # https://bug.oraclecorp.com/pls/bug/webbug_edit.edit_info_top?rptno=10631565
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc519774"
  );
  # https://bug.oraclecorp.com/pls/bug/webbug_edit.edit_info_top?rptno=13494054
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f23ffdff"
  );
  # https://forums.oracle.com/forums/thread.jspa?threadID=2347014&amp;tstart=0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a21b79d3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2012-June/000083.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/13");
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
if (rpm_check(release:"OVS3.0", reference:"xen-4.0.0-81.el5.7")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-devel-4.0.0-81.el5.7")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-tools-4.0.0-81.el5.7")) flag++;

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
