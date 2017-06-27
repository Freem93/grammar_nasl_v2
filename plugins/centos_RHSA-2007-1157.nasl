# @DEPRECATED@
#
# This script has been deprecated as the associated updates are for
# CENTOSPLUS only.
#
# Disabled on 2013/06/28.

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1155 and 
# CentOS Errata and Security Advisory 2007:1222-001 respectively.
#

include("compat.inc");

if (description)
{
  script_id(29752);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/29 01:11:30 $");

  script_cve_id("CVE-2007-5925", "CVE-2007-5969", "CVE-2007-6303");
  script_xref(name:"RHSA", value:"2007:1157");

  script_name(english:"CentOS 4 : mysql (CESA-2007:1222-001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been
documented in Red Hat advisory RHSA-2007-1157.");
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62057dab"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3be7e9e1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


# Deprecated.
exit(0, "The associated patches are for CENTOSPLUS only.");

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
if ( rpm_check(reference:"mysql-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"mysql-bench-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"mysql-cluster-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"mysql-devel-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"mysql-libs-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"mysql-server-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"mysql-test-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"mysql-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"x86_64") ) flag ++;
if ( rpm_check(reference:"mysql-bench-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"x86_64") ) flag ++;
if ( rpm_check(reference:"mysql-cluster-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"x86_64") ) flag ++;
if ( rpm_check(reference:"mysql-devel-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"x86_64") ) flag ++;
if ( rpm_check(reference:"mysql-libs-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"x86_64") ) flag ++;
if ( rpm_check(reference:"mysql-server-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"x86_64") ) flag ++;
if ( rpm_check(reference:"mysql-test-5.0.48-2.el4.centos", release:"CentOS-4", cpu:"x86_64") ) flag ++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
