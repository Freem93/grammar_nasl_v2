# @DEPRECATED@
#
# This script has been deprecated as the associated postings listed the
# incorrect set of packages. 
#
# Disabled on 2013/06/28.

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0818 and 
# CentOS Errata and Security Advisory 2008:0818 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43705);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/29 01:35:48 $");

  script_cve_id("CVE-2008-2940", "CVE-2008-2941");

  script_name(english:"CentOS 5 : hplip (CESA-2008-0818)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value: 
"The remote CentOS system is missing a security update which has been
documented in Red Hat advisory RHSA-2008-0818."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015189.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7624c7d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64b78714"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015191.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?439ffc9b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015192.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7a35d6c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


# Deprecated.
exit(0, "The associated postings list the incorrect set of packages.");

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
if ( rpm_check(reference:"postfix-2.3.3-2.1.el5_2", release:"CentOS-5", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"postfix-pflogsumm-2.3.3-2.1.el5_2", release:"CentOS-5", cpu:"i386") ) flag ++;
if ( rpm_check(reference:"postfix-2.3.3-2.1.el5_2", release:"CentOS-5", cpu:"x86_64") ) flag ++;
if ( rpm_check(reference:"postfix-pflogsumm-2.3.3-2.1.el5_2", release:"CentOS-5", cpu:"x86_64") ) flag ++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
