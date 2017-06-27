#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0349. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(58194);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 16:14:07 $");

  script_xref(name:"RHSA", value:"2012:0349");

  script_name(english:"RHEL 4 : redhat-release (EOL Notice) (RHSA-2012:0349)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Enterprise Linux 4 reaches end of Production Phase and
transitions to Extended Life Phase.

On March 01, 2012, all Red Hat Enterprise Linux 4-based products
listed below transition from the Production Phase to the Extended Life
Phase :

Red Hat Enterprise Linux AS 4 Red Hat Enterprise Linux ES 4 Red Hat
Enterprise Linux WS 4 Red Hat Desktop 4 Red Hat Global File System 4
Red Hat Cluster Suite 4

Red Hat offers support and services for each major release of Red Hat
Enterprise Linux throughout four phases - Production 1, 2, and 3,
and Extended Life Phase. For Red Hat Enterprise Linux 4, the
Production Phase spans seven years, followed by a three-year Extended
Life Phase. Together, these four phases constitute the 'life cycle'.
The specific support and services provided during each phase is
described in detail at: http://redhat.com/rhel/lifecycle

On March 01, 2012, Red Hat Enterprise Linux 4 systems continue to be
subscribed to Red Hat Enterprise Linux 4 channels on Red Hat Network
(RHN), continue to require a Red Hat Enterprise Linux entitlement, and
continue to have access to :

* Limited technical support for existing Red Hat Enterprise Linux 4
deployments (for customers with Basic, Premium, or Standard support).

* Previously released bug fixes (RHBAs), security errata (RHSAs), and
product enhancements (RHEAs) via RHN. Software maintenance (new bug
fix and security errata) are no longer provided for the Red Hat
Enterprise Linux 4 product family.

* Red Hat Knowledgebase and other content (white papers, reference
architectures, etc.) found in the Red Hat Customer Portal.

* Red Hat Enterprise Linux 4 documentation.

Please also note that new bug fix, security, or product enhancements
advisories (RHBAs, RHSAs, and RHEAs) are no longer provided for the
Red Hat Enterprise Linux 4 Add-Ons after March 01.

After March 01, you have several options. Your Red Hat subscription
gives you continuous access to all active versions of the Red Hat
software in both binary and source form, including all security
updates and bug fixes. As Red Hat Enterprise Linux 4 transitions out
of the Production Phase, we strongly recommend that you take full
advantage of your subscription services and upgrade to Red Hat
Enterprise Linux 5 or 6, which contain compelling new features and
enablement for modern hardware platforms and ISV applications.

If you must remain on Red Hat Enterprise Linux 4, we recommend that
you add the Red Hat Enterprise Linux Extended Life Cycle Support (ELS)
Add-On subscription to your current Red Hat Enterprise Linux
subscription. The ELS Add-On complements your Red Hat Enterprise Linux
subscription and provides software maintenance services not otherwise
available in the Extended Life Phase. Customers who purchase the ELS
Add-On continue to receive software maintenance (critical impact
security and urgent priority bug fixes) and technical support as
provided in the Production 3 Phase. ELS is available for up to three
years and requires that you have an existing Red Hat Enterprise Linux
subscription with equivalent subscription terms and support level.

For more information on the Red Hat Enterprise Linux ELS Add-On,
visit: http://www.redhat.com/products/enterprise-linux-add-ons/
extended-lifecycle-support/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/products/enterprise-linux-add-ons/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://redhat.com/rhel/lifecycle"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0349.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL4", reference:"redhat-release-4AS-10.10")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"redhat-release-4WS-10.10")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"redhat-release-4ES-10.10")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"redhat-release-4ES-10.10")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"redhat-release-4WS-10.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
