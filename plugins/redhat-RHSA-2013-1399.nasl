#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1399. The text 
# itself is copyright (C) Red Hat, Inc.
#

# @DEPRECATED@
#
# This script has been deprecated as it has been determined to
# be a non-security noficiation advisory with no security
# updates.
#
# Disabled on 2014/07/29.
#


include("compat.inc");

if (description)
{
  script_id(76668);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/29 18:36:34 $");

  script_xref(name:"RHSA", value:"2013:1399");

  script_name(english:"RHEL 5 : MRG (RHSA-2013:1399) (deprecated)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the 6-month notification for the retirement of Red Hat
Enterprise MRG Version 1 and Version 2 for Red Hat Enterprise Linux 5.

In accordance with the Red Hat Enterprise MRG Life Cycle policy, the
Red Hat Enterprise MRG products, which include the MRG-Messaging,
MRG-Realtime, and MRG-Grid, Version 1 and Version 2 offerings for Red
Hat Enterprise Linux 5 will be retired as of March 31, 2014, and
support will no longer be provided.

Accordingly, Red Hat will no longer provide updated packages,
including critical impact security patches or urgent priority bug
fixes, for MRG-Messaging, MRG-Realtime, and MRG-Grid on Red Hat
Enterprise Linux 5 after that date. In addition, technical support
through Red Hat's Global Support Services will no longer be provided
for these products on Red Hat Enterprise Linux 5 after March 31, 2014.

Note: This notification applies only to those customers with
subscriptions for Red Hat Enterprise MRG Version 1 and Version 2 for
Red Hat Enterprise Linux 5.

We encourage customers to plan their migration from Red Hat Enterprise
MRG Version 1 and Version 2 for Red Hat Enterprise Linux 5 to Red Hat
Enterprise MRG Version 2 on Red Hat Enterprise Linux 6. As a benefit
of the Red Hat subscription model, customers can use their active Red
Hat Enterprise MRG subscriptions to entitle any system on a currently
supported version of that product.

Details of the Red Hat Enterprise MRG life cycle can be found here:
https://access.redhat.com/support/policy/updates/mrg/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/policy/updates/mrg/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1399.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mrg-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The advisory contains no security updates.");

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

if (! (rpm_exists(release:"RHEL5", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

if (rpm_check(release:"RHEL5", reference:"mrg-release-1.3.3-3.el5")) flag++;
if (rpm_check(release:"RHEL5", reference:"mrg-release-2.4.0-3.el5_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
