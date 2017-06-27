#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0297. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35757);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_xref(name:"RHSA", value:"2009:0297");

  script_name(english:"RHEL 2.1 : redhat-release (EOL Notice) (RHSA-2009:0297)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the 3-month notification of the End Of Life plans for Red Hat
Enterprise Linux 2.1.

In accordance with the Red Hat Enterprise Linux Errata Support Policy,
the 7 years life cycle of Red Hat Enterprise Linux 2.1 will end on May
31 2009.

After that date, Red Hat will discontinue the technical support
services, bugfix, enhancement and security errata updates for the
following products :

* Red Hat Enterprise Linux AS 2.1 * Red Hat Enterprise Linux ES 2.1 *
Red Hat Enterprise Linux WS 2.1 * Red Hat Linux Advanced Server 2.1 *
Red Hat Linux Advanced Workstation 2.1

Customers running production workloads on Enterprise Linux 2.1 should
plan to migrate to a later version before May 31, 2009. One benefit of
a Red Hat subscription is the right to upgrade to never versions of
Enterprise Linux for no extra cost. As an Enterprise Linux subscriber,
you have the option of migrating to the following supported versions :

* version 3 (Generally Available: Oct 2003, End-Of-Life: Oct 2010) *
version 4 (GA: Feb 2005, EOL: Feb 2012) * version 5 (GA: Mar 2007,
EOL: Mar 2014)

These supported versions of Enterprise Linux are available for
download from Red Hat Network.

For those customers who cannot migrate from Enterprise Linux 2.1
before its end-of-life date, Red Hat will offer limited extended
support contracts. For more information, contact your Red Hat sales
representative.

Details of the Red Hat Enterprise Linux life cycle can be found on the
Red Hat website: http://www.redhat.com/security/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/security/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0297.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected redhat-release-as, redhat-release-es and / or
redhat-release-ws packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-ws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"redhat-release-as-2.1AS-24")) flag++;
if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"redhat-release-es-2.1ES-24")) flag++;
if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"redhat-release-ws-2.1WS-24")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
