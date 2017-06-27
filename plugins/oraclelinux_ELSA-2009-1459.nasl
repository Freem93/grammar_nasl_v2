#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1459 and 
# Oracle Linux Security Advisory ELSA-2009-1459 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67930);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 16:53:47 $");

  script_cve_id("CVE-2009-2632", "CVE-2009-3235");
  script_bugtraq_id(36296, 36377);
  script_xref(name:"RHSA", value:"2009:1459");

  script_name(english:"Oracle Linux 4 / 5 : cyrus-imapd (ELSA-2009-1459)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1459 :

Updated cyrus-imapd packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and Sieve support.

Multiple buffer overflow flaws were found in the Cyrus IMAP Sieve
implementation. An authenticated user able to create Sieve mail
filtering rules could use these flaws to execute arbitrary code with
the privileges of the Cyrus IMAP server user. (CVE-2009-2632,
CVE-2009-3235)

Users of cyrus-imapd are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing the update, cyrus-imapd will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001163.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL4", reference:"cyrus-imapd-2.2.12-10.0.1.el4_8.4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-devel-2.2.12-10.0.1.el4_8.4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-murder-2.2.12-10.0.1.el4_8.4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-nntp-2.2.12-10.0.1.el4_8.4")) flag++;
if (rpm_check(release:"EL4", reference:"cyrus-imapd-utils-2.2.12-10.0.1.el4_8.4")) flag++;
if (rpm_check(release:"EL4", reference:"perl-Cyrus-2.2.12-10.0.1.el4_8.4")) flag++;

if (rpm_check(release:"EL5", reference:"cyrus-imapd-2.3.7-7.0.1.el5_4.3")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-devel-2.3.7-7.0.1.el5_4.3")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-perl-2.3.7-7.0.1.el5_4.3")) flag++;
if (rpm_check(release:"EL5", reference:"cyrus-imapd-utils-2.3.7-7.0.1.el5_4.3")) flag++;


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
