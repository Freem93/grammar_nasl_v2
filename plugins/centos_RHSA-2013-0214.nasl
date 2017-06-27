#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0214 and 
# CentOS Errata and Security Advisory 2013:0214 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67097);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_xref(name:"RHSA", value:"2013:0214");

  script_name(english:"CentOS 5 : nss (CESA-2013:0214)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nspr packages that fix one security issue, various
bugs, and add enhancements are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

It was found that a Certificate Authority (CA) mis-issued two
intermediate certificates to customers. These certificates could be
used to launch man-in-the-middle attacks. This update renders those
certificates as untrusted. This covers all uses of the certificates,
including SSL, S/MIME, and code signing. (BZ#890605)

In addition, the nss package has been upgraded to upstream version
3.13.6, and the nspr package has been upgraded to upstream version
4.9.2. These updates provide a number of bug fixes and enhancements
over the previous versions. (BZ#893371, BZ#893372)

All NSS and NSPR users should upgrade to these updated packages, which
correct these issues and add these enhancements. After installing the
update, applications using NSS and NSPR must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019218.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?622183fd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"nspr-4.9.2-2.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.9.2-2.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.13.6-3.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.13.6-3.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.13.6-3.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.13.6-3.el5_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
