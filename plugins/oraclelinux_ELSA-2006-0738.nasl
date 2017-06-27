#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0738 and 
# Oracle Linux Security Advisory ELSA-2006-0738 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67425);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-5794");
  script_osvdb_id(30232);
  script_xref(name:"RHSA", value:"2006:0738");

  script_name(english:"Oracle Linux 3 / 4 : openssh (ELSA-2006-0738)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0738 :

Updated openssh packages that fix an authentication flaw are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
package includes the core files necessary for both the OpenSSH client
and server.

An authentication flaw was found in OpenSSH's privilege separation
monitor. If it ever becomes possible to alter the behavior of the
unprivileged process when OpenSSH is using privilege separation, an
attacker may then be able to login without possessing proper
credentials. (CVE-2006-5794)

Please note that this flaw by itself poses no direct threat to OpenSSH
users. Without another security flaw that could allow an attacker to
alter the behavior of OpenSSH's unprivileged process, this flaw cannot
be exploited. There are currently no known flaws to exploit this
behavior. However, we have decided to issue this erratum to fix this
flaw to reduce the security impact if an unprivileged process flaw is
ever found.

Users of openssh should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000089.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssh-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssh-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssh-askpass-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssh-askpass-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssh-askpass-gnome-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssh-askpass-gnome-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssh-clients-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssh-clients-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssh-server-3.6.1p2-33.30.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssh-server-3.6.1p2-33.30.13")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-askpass-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-askpass-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-clients-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-clients-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-server-3.9p1-8.RHEL4.17.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-server-3.9p1-8.RHEL4.17.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-askpass-gnome / openssh-clients / etc");
}
