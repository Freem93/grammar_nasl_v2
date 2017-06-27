#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1282 and 
# CentOS Errata and Security Advisory 2011:1282 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56274);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_xref(name:"RHSA", value:"2011:1282");

  script_name(english:"CentOS 4 / 5 : nspr / nss (CESA-2011:1282)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nspr packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

Netscape Portable Runtime (NSPR) provides platform independence for
non-GUI operating system facilities.

It was found that a Certificate Authority (CA) issued fraudulent HTTPS
certificates. This update renders any HTTPS certificates signed by
that CA as untrusted. This covers all uses of the certificates,
including SSL, S/MIME, and code signing. (BZ#734316)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

These updated packages upgrade NSS to version 3.12.10 on Red Hat
Enterprise Linux 4 and 5. As well, they upgrade NSPR to version 4.8.8
on Red Hat Enterprise Linux 4 and 5, as required by the NSS update.
The packages for Red Hat Enterprise Linux 6 include a backported
patch.

All NSS and NSPR users should upgrade to these updated packages, which
correct this issue. After installing the update, applications using
NSS and NSPR must be restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017913.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12df0c99"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017915.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?244a5a9e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10e25e8c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018069.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bc4ff2e"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000312.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ccce325"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcf1d9f1"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000314.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?539d2561"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000315.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7cb18b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-4.8.8-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-4.8.8-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-devel-4.8.8-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-devel-4.8.8-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-3.12.10-4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-3.12.10-4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-devel-3.12.10-4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-devel-3.12.10-4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-tools-3.12.10-4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-tools-3.12.10-4.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"nspr-4.8.8-1.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.8.8-1.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.12.10-4.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.10-4.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.10-4.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.10-4.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
