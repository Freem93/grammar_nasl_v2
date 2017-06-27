#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0817. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50446);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_xref(name:"RHSA", value:"2010:0817");

  script_name(english:"RHEL 3 : redhat-release (EOL Notice) (RHSA-2010:0817)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the End Of Life notification for Red Hat Enterprise Linux 3.

In accordance with the Red Hat Enterprise Linux Errata Support Policy,
the regular 7 year life cycle of Red Hat Enterprise Linux 3 has ended.

Red Hat has discontinued the regular subscription services for Red Hat
Enterprise Linux 3. Therefore, new bug fix, enhancement, and security
errata updates, as well as technical support services are no longer
available for the following products :

* Red Hat Enterprise Linux AS 3 * Red Hat Enterprise Linux ES 3 * Red
Hat Enterprise Linux WS 3 * Red Hat Enterprise Linux Extras 3 * Red
Hat Desktop 3 * Red Hat Global File System 3 * Red Hat Cluster Suite 3

Servers subscribed to Red Hat Enterprise Linux 3 channels on the Red
Hat Network will shortly become unsubscribed. As a benefit of the Red
Hat subscription model, those subscriptions can be used to entitle any
system on any currently supported release of Red Hat Enterprise Linux.

Red Hat Enterprise Linux Subscriptions are version-independent and
allow access to all major releases of Red Hat Enterprise Linux, that
are currently supported within their regular 7-year life cycle.
Therefore customers retain access to Red Hat Enterprise Linux 4, 5 and
soon to be released 6. There are no additional upgrade fees when
moving from Red Hat Enterprise Linux 3 to any of these newer releases.

For customers who are unable to migrate off Red Hat Enterprise Linux
3, Red Hat is offering a limited, optional extension program referred
to as RHEL 3 Extended Life Cycle Support (ELS). For more information,
contact your Red Hat sales representative or channel partner on this
program. Additionally you can find more information on this program
here: http://www.redhat.com/rhel/server/extended_lifecycle_support/

Once you are eligible for subscribing to the RHEL 3 ELS channels, read
the Red Hat Knowledgebase article DOC-40489 at
https://access.redhat.com/kb/docs/DOC-40489 for detailed information
on how to subscribe to the RHEL 3 ELS channels.

Details of the Red Hat Enterprise Linux life cycle can be found on the
Red Hat website: http://www.redhat.com/security/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/kb/docs/DOC-40489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/security/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/rhel/server/extended_lifecycle_support/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0817.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL3", reference:"redhat-release-3AS-13.9.11")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"redhat-release-3WS-13.9.11")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"redhat-release-3ES-13.9.11")) flag++;
if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"redhat-release-3ES-13.9.11")) flag++;
if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"redhat-release-3WS-13.9.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
