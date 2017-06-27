#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0522 and 
# CentOS Errata and Security Advisory 2014:0522 respectively.
#

include("compat.inc");

if (description)
{
  script_id(74128);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/05/22 11:28:00 $");

  script_xref(name:"RHSA", value:"2014:0522");

  script_name(english:"CentOS 6 : Moderate: / mariadb55-mariadb (CESA-2014:0522)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2014:0522."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2014-May/020309.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb55-mariadb and / or moderate: packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-5.5.37-1.3.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-bench-5.5.37-1.3.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-devel-5.5.37-1.3.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-libs-5.5.37-1.3.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-server-5.5.37-1.3.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-test-5.5.37-1.3.el6.centos.alt")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
