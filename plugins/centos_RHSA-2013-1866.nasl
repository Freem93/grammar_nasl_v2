#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1866 and 
# CentOS Errata and Security Advisory 2013:1866 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71540);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/06 10:39:18 $");

  script_xref(name:"RHSA", value:"2013:1866");

  script_name(english:"CentOS 6 : ca-certificates (CESA-2013:1866)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ca-certificates package that fixes one security issue is
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact.

This package contains the set of CA certificates chosen by the Mozilla
Foundation for use with the Internet Public Key Infrastructure (PKI).

It was found that a subordinate Certificate Authority (CA) mis-issued
an intermediate certificate, which could be used to conduct
man-in-the-middle attacks. This update renders that particular
intermediate certificate as untrusted. (BZ#1038894)

All users should upgrade to this updated package. After installing the
update, all applications using the ca-certificates package must be
restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62ed90e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ca-certificates package."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ca-certificates");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ca-certificates-2013.1.95-65.1.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
