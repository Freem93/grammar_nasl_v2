#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1444. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56766);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_xref(name:"RHSA", value:"2011:1444");

  script_name(english:"RHEL 4 / 5 / 6 : nss (RHSA-2011:1444)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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

It was found that the Malaysia-based Digicert Sdn. Bhd. subordinate
Certificate Authority (CA) issued HTTPS certificates with weak keys.
This update renders any HTTPS certificates signed by that CA as
untrusted. This covers all uses of the certificates, including SSL,
S/MIME, and code signing. Note: Digicert Sdn. Bhd. is not the same
company as found at digicert.com. (BZ#751366)

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

This update also fixes the following bug on Red Hat Enterprise Linux 
5 :

* When using mod_nss with the Apache HTTP Server, a bug in NSS on Red
Hat Enterprise Linux 5 resulted in file descriptors leaking each time
the Apache HTTP Server was restarted with the 'service httpd reload'
command. This could have prevented the Apache HTTP Server from
functioning properly if all available file descriptors were consumed.
(BZ#743508)

For Red Hat Enterprise Linux 6, these updated packages upgrade NSS to
version 3.12.10. As well, they upgrade NSPR (Netscape Portable
Runtime) to version 4.8.8 and nss-util to version 3.12.10 on Red Hat
Enterprise Linux 6, as required by the NSS update. (BZ#735972,
BZ#736272, BZ#735973)

All NSS users should upgrade to these updated packages, which correct
this issue. After installing the update, applications using NSS must
be restarted for the changes to take effect. In addition, on Red Hat
Enterprise Linux 6, applications using NSPR and nss-util must also be
restarted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1444.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1444";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"nss-3.12.10-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-devel-3.12.10-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-tools-3.12.10-6.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"nss-3.12.10-7.el5_7")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-devel-3.12.10-7.el5_7")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-pkcs11-devel-3.12.10-7.el5_7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nss-tools-3.12.10-7.el5_7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nss-tools-3.12.10-7.el5_7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nss-tools-3.12.10-7.el5_7")) flag++;


  if (rpm_check(release:"RHEL6", reference:"nspr-4.8.8-1.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nspr-debuginfo-4.8.8-1.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nspr-devel-4.8.8-1.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-debuginfo-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-devel-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-pkcs11-devel-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-sysinit-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-sysinit-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-sysinit-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-tools-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-tools-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-tools-3.12.10-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-3.12.10-1.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-debuginfo-3.12.10-1.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-devel-3.12.10-1.el6_1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / nss / nss-debuginfo / etc");
  }
}
