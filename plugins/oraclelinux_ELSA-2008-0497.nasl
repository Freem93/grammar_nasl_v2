#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0497 and 
# Oracle Linux Security Advisory ELSA-2008-0497 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67698);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:41:02 $");

  script_cve_id("CVE-2008-1951");
  script_osvdb_id(46547);
  script_xref(name:"RHSA", value:"2008:0497");

  script_name(english:"Oracle Linux 4 / 5 : sblim (ELSA-2008-0497)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0497 :

Updated sblim packages that resolve a security issue are now available
for Red Hat Enterprise Linux 4 and Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SBLIM stands for Standards-Based Linux Instrumentation for
Manageability. It consists of a set of standards-based, Web-Based
Enterprise Management (WBEM) modules that use the Common Information
Model (CIM) standard to gather and provide systems management
information, events, and methods to local or networked consumers via a
CIM object services broker using the CMPI (Common Manageability
Programming Interface) standard. This package provides a set of core
providers and development tools for systems management applications.

It was discovered that certain sblim libraries had an RPATH (runtime
library search path) set in the ELF (Executable and Linking Format)
header. This RPATH pointed to a sub-directory of a world-writable,
temporary directory. A local user could create a file with the same
name as a library required by sblim (such as libc.so) and place it in
the directory defined in the RPATH. This file could then execute
arbitrary code with the privileges of the user running an application
that used sblim (eg tog-pegasus). (CVE-2008-1951)

Users are advised to upgrade to these updated sblim packages, which
resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-June/000654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-June/000655.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sblim packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cim-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cim-client-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cim-client-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-base-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-dns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-dns-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-fsvol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-fsvol-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-fsvol-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-network-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-params-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-sysfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-sysfs-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-syslog-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-tools-libra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-tools-libra-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-wbemcli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-base-1.5.4-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-base-devel-1.5.4-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-base-test-1.5.4-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-devel-1.0.4-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-fsvol-1.4.3-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-fsvol-test-1.4.3-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-network-1.3.7-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-network-devel-1.3.7-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-network-test-1.3.7-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-nfsv3-1.0.13-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-nfsv4-1.0.11-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-params-1.2.4-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-params-test-1.2.4-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-sysfs-1.1.8-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-sysfs-test-1.1.8-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-syslog-0.7.9-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-cmpi-syslog-test-0.7.9-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-gather-2.1.1-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-gather-devel-2.1.1-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-gather-provider-2.1.1-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-gather-test-2.1.1-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-testsuite-1.2.4-13a.0.1.el4_6.1")) flag++;
if (rpm_check(release:"EL4", reference:"sblim-wbemcli-1.5.1-13a.0.1.el4_6.1")) flag++;

if (rpm_check(release:"EL5", reference:"sblim-cim-client-1.3.3-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cim-client-javadoc-1-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cim-client-manual-1-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-base-1.5.5-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-base-devel-1.5.5-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-base-test-1.5.5-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-devel-1.0.4-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-dns-0.5.2-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-dns-devel-1-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-dns-test-1-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-fsvol-1.4.4-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-fsvol-devel-1.4.4-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-fsvol-test-1.4.4-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-network-1.3.8-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-network-devel-1.3.8-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-network-test-1.3.8-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-nfsv3-1.0.14-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-nfsv3-test-1.0.14-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-nfsv4-1.0.12-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-nfsv4-test-1.0.12-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-params-1.2.6-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-params-test-1.2.6-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-samba-0.5.2-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-samba-devel-1-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-samba-test-1-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-sysfs-1.1.9-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-sysfs-test-1.1.9-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-syslog-0.7.11-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-cmpi-syslog-test-0.7.11-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-gather-2.1.2-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-gather-devel-2.1.2-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-gather-provider-2.1.2-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-gather-test-2.1.2-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-testsuite-1.2.4-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-tools-libra-0.2.3-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-tools-libra-devel-0.2.3-31.0.1.el5_2.1")) flag++;
if (rpm_check(release:"EL5", reference:"sblim-wbemcli-1.5.1-31.0.1.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sblim-cim-client / sblim-cim-client-javadoc / etc");
}
