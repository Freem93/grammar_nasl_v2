#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1239. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63997);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/21 17:37:48 $");

  script_xref(name:"RHSA", value:"2011:1239");

  script_name(english:"RHEL 4 : redhat-release (EOL Notice) (RHSA-2011:1239)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the End of Life notification for Red Hat Enterprise Linux
Extended Update Support Add-On (EUS) 4.7.

In accordance with the Red Hat Enterprise Linux Errata Support Policy,
the Extended Update Support for Red Hat Enterprise Linux 4 Update 7
has ended.

Note: This does not impact you unless you are subscribed to the
Extended Update Support (EUS) channel for Red Hat Enterprise Linux
4.7.

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
    value:"http://rhn.redhat.com/errata/RHSA-2011-1239.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL4", sp:"7", reference:"redhat-release-4AS-8.0.el4_7.4")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i386", reference:"redhat-release-4ES-8.0.el4_7.4")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"redhat-release-4ES-8.0.el4_7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
