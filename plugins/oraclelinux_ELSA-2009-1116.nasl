#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1116 and 
# Oracle Linux Security Advisory ELSA-2009-1116 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67877);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:41:03 $");

  script_cve_id("CVE-2009-0688");
  script_xref(name:"RHSA", value:"2009:1116");

  script_name(english:"Oracle Linux 4 / 5 : cyrus-imapd (ELSA-2009-1116)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1116 :

Updated cyrus-imapd packages that fix a security issue are now
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
    value:"https://oss.oracle.com/pipermail/el-errata/2009-June/001050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-June/001051.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-nntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Cyrus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/18");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-2.2.12-10.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-devel-2.2.12-10.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-murder-2.2.12-10.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-nntp-2.2.12-10.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-utils-2.2.12-10.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"perl-Cyrus-2.2.12-10.0.1.el4_8.1")) flag++;

if (rpm_check(release:"EL5", reference:"cyrus-imapd-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-devel-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-perl-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-utils-2.3.7-2.el5_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-devel / cyrus-imapd-murder / etc");
}
