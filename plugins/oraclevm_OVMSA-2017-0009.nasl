#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0009.
#

include("compat.inc");

if (description)
{
  script_id(96522);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2016-10013", "CVE-2016-10024");
  script_osvdb_id(149021, 149100);
  script_xref(name:"IAVB", value:"2017-B-0008");

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2017-0009)");
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

  - From: Jan Beulich Subject: x86: force EFLAGS.IF on when
    exiting to PV guests Guest kernels modifying
    instructions in the process of being emulated for
    another of their vCPU-s may effect EFLAGS.IF to be
    cleared upon next exiting to guest context, by
    converting the being emulated instruction to CLI (at the
    right point in time). Prevent any such bad effects by
    always forcing EFLAGS.IF on. And to cover hypothetical
    other similar issues, also force EFLAGS.[IOPL,NT,VM] to
    zero. This is XSA-202.

    Conflict: xen/arch/x86/x86_64/compat/entry.S
    (CVE-2016-10024)

  - From 4d246723a85a03406e4969a260291e11b8e05960 Mon Sep 17
    00:00:00 2001 x86: use MOV instead of PUSH/POP when
    saving/restoring register state (CVE-2016-10024)

  - From: Andrew Cooper Date: Sun, 18 Dec 2016 15:42:59
    +0000 Subject: [PATCH] x86/emul: Correct the handling of
    eflags with SYSCALL A singlestep #DB is determined by
    the resulting eflags value from the execution of
    SYSCALL, not the original eflags value. By using the
    original eflags value, we negate the guest kernels
    attempt to protect itself from a privilege escalation by
    masking TF. Introduce a tf boolean and have the SYSCALL
    emulation recalculate it after the instruction is
    complete. This is XSA-204

    Conflict: xen/arch/x86/x86_emulate/x86_emulate.c
    (CVE-2016-10013)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-January/000620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddde1577"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/16");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.223.49")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.223.49")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.223.49")) flag++;

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
