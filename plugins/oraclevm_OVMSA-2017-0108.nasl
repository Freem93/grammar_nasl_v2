#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0108.
#

include("compat.inc");

if (description)
{
  script_id(100399);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_cve_id("CVE-2017-8779");
  script_osvdb_id(157016, 157017);

  script_name(english:"OracleVM 3.3 / 3.4 : libtirpc (OVMSA-2017-0108)");
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

  - Fix for CVE-2017-8779 (bz 1449458)

  - tirpc: fix taddr2uaddr for AF_LOCAL (bz 1285144)

  - clnt_vc_create: Do not hold a global mutex during
    connect (bz 1332520)

  - Backported upstream debugging (bz 1273158)

  - Fixed memory leak in svc_vc_create (bz 1276687)

  - Fixed memory leak in svc_tli_create (bz 1276855)

  - Fixed memory leak in __svc_vc_dodestroy (bz 1276856)

  - xdr_rejected_reply: Don't crash with invalid server
    rejection (bz 982064)

  - Fixed overrun in svcauth_gss_validate (bz 1056809)

  - Added authgss_free_private_data call (bz 1082807)

  - Fixed some races in getnetconfig code (bz 1031498)

  - Remove the installation of libtirpc.a and libtirpc.la
    (bz 869397)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000731.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtirpc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libtirpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"libtirpc-0.2.1-13.el6_9")) flag++;

if (rpm_check(release:"OVS3.4", reference:"libtirpc-0.2.1-13.el6_9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtirpc");
}
