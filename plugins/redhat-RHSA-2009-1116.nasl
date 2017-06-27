#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1116. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39461);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-0688");
  script_xref(name:"RHSA", value:"2009:1116");

  script_name(english:"RHEL 4 / 5 : cyrus-imapd (RHSA-2009:1116)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cyrus-imapd packages that fix a security issue are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and SIEVE support.

It was discovered that the Cyrus SASL library (cyrus-sasl) does not
always reliably terminate output from the sasl_encode64() function
used by programs using this library. The Cyrus IMAP server
(cyrus-imapd) relied on this function's output being properly
terminated. Under certain conditions, improperly terminated output
from sasl_encode64() could, potentially, cause cyrus-imapd to crash,
disclose portions of its memory, or lead to SASL authentication
failures. (CVE-2009-0688)

Users of cyrus-imapd are advised to upgrade to these updated packages,
which resolve this issue. After installing the update, cyrus-imapd
will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1116.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-nntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Cyrus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1116";
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
  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-2.2.12-10.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-devel-2.2.12-10.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-murder-2.2.12-10.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-nntp-2.2.12-10.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-utils-2.2.12-10.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"perl-Cyrus-2.2.12-10.el4_8.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cyrus-imapd-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cyrus-imapd-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cyrus-imapd-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"cyrus-imapd-devel-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cyrus-imapd-perl-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cyrus-imapd-perl-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cyrus-imapd-perl-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cyrus-imapd-utils-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cyrus-imapd-utils-2.3.7-2.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cyrus-imapd-utils-2.3.7-2.el5_3.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-devel / cyrus-imapd-murder / etc");
  }
}
