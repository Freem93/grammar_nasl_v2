#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1861 and 
# CentOS Errata and Security Advisory 2013:1861 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71539);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_xref(name:"RHSA", value:"2013:1861");

  script_name(english:"CentOS 5 / 6 : nss (CESA-2013:1861)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix one security issue are now available for
Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

It was found that a subordinate Certificate Authority (CA) mis-issued
an intermediate certificate, which could be used to conduct
man-in-the-middle attacks. This update renders that particular
intermediate certificate as untrusted. (BZ#1038894)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

All NSS users should upgrade to these updated packages, which correct
this issue. After installing the update, applications using NSS must
be restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f1873f2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67f70d32"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"nss-3.15.3-4.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.15.3-4.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.15.3-4.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.15.3-4.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"nss-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.15.3-3.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
