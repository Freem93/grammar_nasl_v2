#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1267 and 
# CentOS Errata and Security Advisory 2011:1267 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56128);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_xref(name:"RHSA", value:"2011:1267");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2011:1267)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes one security issue is now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Mozilla Thunderbird is a standalone mail and newsgroup client.

The RHSA-2011:1243 Thunderbird update rendered HTTPS certificates
signed by a certain Certificate Authority (CA) as untrusted, but made
an exception for a select few. This update removes that exception,
rendering every HTTPS certificate signed by that CA as untrusted.
(BZ#735483)

All Thunderbird users should upgrade to this updated package, which
resolves this issue. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc6f8966"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76214017"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018044.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96a1cc58"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018045.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca404fde"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000302.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ee1cd3e"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000303.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d7a8e5a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-43.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-43.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.24-25.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
