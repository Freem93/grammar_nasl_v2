#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0073. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57759);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_xref(name:"RHSA", value:"2012:0073");

  script_name(english:"RHEL 4 : redhat-release (EOL Notice) (RHSA-2012:0073)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the 30 day notification of the End Of Life plans for Red Hat
Enterprise Linux 4.

In accordance with the Red Hat Enterprise Linux Errata Support Policy,
the 7 year life cycle of Red Hat Enterprise Linux 4 will end on
February 29, 2012 and your subscription services for that version will
change. Active Red Hat Enterprise Linux subscribers using Red Hat
Enterprise Linux 4 will have the option to upgrade to currently
supported versions of Red Hat Enterprise Linux and receive the full
benefits of the subscription.

After February 29, 2012, Red Hat will discontinue technical support
services as well as software maintenance services for Red Hat
Enterprise Linux 4 meaning that new bug fixes, security errata and
product enhancements will no longer be provided for the following
products :

* Red Hat Enterprise Linux AS 4 * Red Hat Enterprise Linux ES 4 * Red
Hat Enterprise Linux WS 4 * Red Hat Desktop 4 * Red Hat Global File
System 4 * Red Hat Cluster Suite 4

Customers who choose to continue to deploy Red Hat Enterprise Linux 4
offerings will continue to have access via Red Hat Network (RHN) to
the following content as part of their active Red Hat Enterprise Linux
subscription :

  - Previously released bug fixes, security errata and
    product enhancements. - Red Hat Knowledge Base and other
    content (whitepapers, reference architectures, etc)
    found in the Red Hat Customer Portal. - All Red Hat
    Enterprise Linux 4 documentation.

Customers are strongly encouraged to take advantage of the upgrade
benefits of their active Red Hat Enterprise Linux subscription and
migrate to an active version of Red Hat Enterprise Linux such as
version 5 or 6.

For customers who are unable to migrate off Red Hat Enterprise Linux 4
before its end-of-life date and require software maintenance and/or
technical support, Red Hat offers an optional support extension called
the Extended Life-cycle Support (ELS) Add-On Subscription. The ELS
Subscription provides up to three additional years of limited Software
Maintenance (Production 3 Phase) for Red Hat Enterprise Linux 4 with
unlimited technical support, critical Security Advisories (RHSAs) and
selected Urgent Priority Bug Advisories (RHBAs). For more information,
contact your Red Hat sales representative or channel partner.

Details of the Red Hat Enterprise Linux life cycle can be found on the
Red Hat website:
https://access.redhat.com/support/policy/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/policy/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0073.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL4", reference:"redhat-release-4AS-10.7")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"redhat-release-4WS-10.7")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"redhat-release-4ES-10.7")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"redhat-release-4ES-10.7")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"redhat-release-4WS-10.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
