#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0497. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33248);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-1951");
  script_osvdb_id(46547);
  script_xref(name:"RHSA", value:"2008:0497");

  script_name(english:"RHEL 4 / 5 : sblim (RHSA-2008:0497)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sblim packages that resolve a security issue are now available
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
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1951.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0497.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cim-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cim-client-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cim-client-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-base-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-dns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-dns-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-fsvol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-fsvol-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-fsvol-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-network-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-nfsv3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-nfsv3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-nfsv4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-nfsv4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-params-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-sysfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-sysfs-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-cmpi-syslog-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-gather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-gather-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-gather-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-gather-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-tools-libra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-tools-libra-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sblim-wbemcli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0497";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-base-1.5.4-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-base-devel-1.5.4-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-base-test-1.5.4-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-devel-1.0.4-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-fsvol-1.4.3-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-fsvol-test-1.4.3-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-network-1.3.7-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-network-devel-1.3.7-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-network-test-1.3.7-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-nfsv3-1.0.13-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-nfsv4-1.0.11-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-params-1.2.4-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-params-test-1.2.4-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-sysfs-1.1.8-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-sysfs-test-1.1.8-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-syslog-0.7.9-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-cmpi-syslog-test-0.7.9-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-gather-2.1.1-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-gather-devel-2.1.1-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-gather-provider-2.1.1-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-gather-test-2.1.1-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-testsuite-1.2.4-13a.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"sblim-wbemcli-1.5.1-13a.el4_6.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cim-client-1.3.3-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cim-client-1.3.3-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cim-client-1.3.3-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cim-client-javadoc-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cim-client-javadoc-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cim-client-javadoc-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cim-client-manual-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cim-client-manual-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cim-client-manual-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-base-1.5.5-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-base-devel-1.5.5-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-base-test-1.5.5-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-base-test-1.5.5-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-base-test-1.5.5-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-devel-1.0.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-dns-0.5.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-dns-devel-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-dns-test-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-dns-test-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-dns-test-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-fsvol-1.4.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-fsvol-devel-1.4.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-fsvol-test-1.4.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-fsvol-test-1.4.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-fsvol-test-1.4.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-network-1.3.8-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-network-devel-1.3.8-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-network-test-1.3.8-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-network-test-1.3.8-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-network-test-1.3.8-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-nfsv3-1.0.14-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-nfsv3-1.0.14-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-nfsv3-1.0.14-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-nfsv3-test-1.0.14-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-nfsv3-test-1.0.14-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-nfsv3-test-1.0.14-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-nfsv4-1.0.12-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-nfsv4-1.0.12-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-nfsv4-1.0.12-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-nfsv4-test-1.0.12-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-nfsv4-test-1.0.12-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-nfsv4-test-1.0.12-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-params-1.2.6-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-params-1.2.6-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-params-1.2.6-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-params-test-1.2.6-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-params-test-1.2.6-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-params-test-1.2.6-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-samba-0.5.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-cmpi-samba-devel-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-samba-test-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-samba-test-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-samba-test-1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-sysfs-1.1.9-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-sysfs-1.1.9-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-sysfs-1.1.9-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-sysfs-test-1.1.9-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-sysfs-test-1.1.9-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-sysfs-test-1.1.9-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-syslog-0.7.11-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-syslog-0.7.11-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-syslog-0.7.11-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-cmpi-syslog-test-0.7.11-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-cmpi-syslog-test-0.7.11-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-cmpi-syslog-test-0.7.11-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-gather-2.1.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-gather-devel-2.1.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-gather-provider-2.1.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-gather-test-2.1.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-gather-test-2.1.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-gather-test-2.1.2-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-testsuite-1.2.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-testsuite-1.2.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-testsuite-1.2.4-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-tools-libra-0.2.3-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"sblim-tools-libra-devel-0.2.3-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sblim-wbemcli-1.5.1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sblim-wbemcli-1.5.1-31.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sblim-wbemcli-1.5.1-31.el5_2.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sblim-cim-client / sblim-cim-client-javadoc / etc");
  }
}
