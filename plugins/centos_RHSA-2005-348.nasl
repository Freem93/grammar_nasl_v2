#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:348 and 
# CentOS Errata and Security Advisory 2005:348 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21926);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
  script_osvdb_id(14676, 14677, 14678);
  script_xref(name:"RHSA", value:"2005:348");

  script_name(english:"CentOS 3 : mysql-server (CESA-2005:348)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2005:348."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4862710"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43bd5664"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09e1ff81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"mysql-3.23.58-16.RHEL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"mysql-bench-3.23.58-16.RHEL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"mysql-devel-3.23.58-16.RHEL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mysql-server-3.23.58-16.RHEL3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
