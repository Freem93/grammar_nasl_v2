#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1282 and 
# Oracle Linux Security Advisory ELSA-2011-1282 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68349);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:58:00 $");

  script_xref(name:"RHSA", value:"2011:1282");

  script_name(english:"Oracle Linux 4 / 5 / 6 : nspr / nss (ELSA-2011-1282)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1282 :

Updated nss and nspr packages that fix one security issue are now
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-September/002348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-September/002349.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-September/002350.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"nspr-4.8.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nspr-devel-4.8.8-1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nss-3.12.10-4.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nss-devel-3.12.10-4.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"nss-tools-3.12.10-4.0.1.el4")) flag++;

if (rpm_check(release:"EL5", reference:"nspr-4.8.8-1.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-devel-4.8.8-1.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"nss-3.12.10-4.0.1.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.12.10-4.0.1.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.12.10-4.0.1.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.12.10-4.0.1.el5_7")) flag++;

if (rpm_check(release:"EL6", reference:"nss-3.12.9-12.0.1.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"nss-devel-3.12.9-12.0.1.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"nss-pkcs11-devel-3.12.9-12.0.1.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"nss-sysinit-3.12.9-12.0.1.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"nss-tools-3.12.9-12.0.1.el6_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / etc");
}
