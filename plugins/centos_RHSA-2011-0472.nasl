#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0472 and 
# CentOS Errata and Security Advisory 2011:0472 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53599);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_xref(name:"RHSA", value:"2011:0472");

  script_name(english:"CentOS 4 / 5 : nss (CESA-2011:0472)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix one security issue are now available for
Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Network Security Services (NSS) is a set of libraries designed to
support the development of security-enabled client and server
applications.

This erratum blacklists a small number of HTTPS certificates by adding
them, flagged as untrusted, to the NSS Builtin Object Token (the
libnssckbi.so library) certificate store. (BZ#689430)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not blacklist the certificates for applications
that use the NSS library, but do not use the NSS Builtin Object Token
(such as curl).

All NSS users should upgrade to these updated packages, which correct
this issue. After installing the update, applications using NSS must
be restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bcebec9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017459.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff53a089"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017466.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2172773"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed0505a6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-3.12.8-3.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-3.12.8-3.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-devel-3.12.8-3.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-devel-3.12.8-3.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-tools-3.12.8-3.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-tools-3.12.8-3.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"nss-3.12.8-4.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.8-4.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.8-4.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.8-4.el5_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
