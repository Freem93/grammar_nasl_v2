#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0497 and 
# CentOS Errata and Security Advisory 2008:0497 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33258);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2008-1951");
  script_osvdb_id(46547);
  script_xref(name:"RHSA", value:"2008:0497");

  script_name(english:"CentOS 4 : sblim (CESA-2008:0497)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0df43ae4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bde61e4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf46d0c7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sblim packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-base-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-fsvol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-fsvol-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-fsvol-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-network-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-nfsv3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-nfsv3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-nfsv4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-nfsv4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-params-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-sysfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-sysfs-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-cmpi-syslog-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-gather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-gather-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-gather-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-gather-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sblim-wbemcli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-base-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-base-1.5.4-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-base-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-base-devel-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-base-devel-1.5.4-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-base-devel-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-base-test-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-base-test-1.5.4-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-base-test-1.5.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-devel-1.0.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-devel-1.0.4-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-devel-1.0.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-fsvol-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-fsvol-1.4.3-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-fsvol-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-fsvol-test-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-fsvol-test-1.4.3-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-fsvol-test-1.4.3-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-network-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-network-1.3.7-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-network-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-network-devel-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-network-devel-1.3.7-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-network-devel-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-network-test-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-network-test-1.3.7-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-network-test-1.3.7-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-nfsv3-1.0.13-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-nfsv3-1.0.13-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-nfsv3-1.0.13-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-nfsv4-1.0.11-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-nfsv4-1.0.11-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-nfsv4-1.0.11-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-params-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-params-1.2.4-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-params-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-params-test-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-params-test-1.2.4-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-params-test-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-sysfs-1.1.8-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-sysfs-1.1.8-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-sysfs-1.1.8-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-sysfs-test-1.1.8-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-sysfs-test-1.1.8-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-sysfs-test-1.1.8-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-syslog-0.7.9-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-syslog-0.7.9-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-syslog-0.7.9-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-cmpi-syslog-test-0.7.9-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-cmpi-syslog-test-0.7.9-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-cmpi-syslog-test-0.7.9-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-gather-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-gather-2.1.1-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-gather-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-gather-devel-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-gather-devel-2.1.1-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-gather-devel-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-gather-provider-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-gather-provider-2.1.1-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-gather-provider-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-gather-test-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-gather-test-2.1.1-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-gather-test-2.1.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-testsuite-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-testsuite-1.2.4-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-testsuite-1.2.4-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"sblim-wbemcli-1.5.1-13a.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sblim-wbemcli-1.5.1-13a.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"sblim-wbemcli-1.5.1-13a.el4_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
