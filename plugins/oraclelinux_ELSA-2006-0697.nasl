#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0697 and 
# Oracle Linux Security Advisory ELSA-2006-0697 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67412);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2006-4924", "CVE-2006-5051", "CVE-2006-5052");
  script_bugtraq_id(20216, 20241);
  script_osvdb_id(29152, 29264, 29266);
  script_xref(name:"RHSA", value:"2006:0697");

  script_name(english:"Oracle Linux 4 : openssh (ELSA-2006-0697)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0697 :

Updated openssh packages that fix two security flaws are now available
for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. This
package includes the core files necessary for both the OpenSSH client
and server.

Mark Dowd discovered a signal handler race condition in the OpenSSH
sshd server. A remote attacker could possibly leverage this flaw to
cause a denial of service (crash). (CVE-2006-5051) The OpenSSH project
believes the likelihood of successful exploitation leading to
arbitrary code execution appears remote. However, the Red Hat Security
Response Team have not yet been able to verify this claim due to lack
of upstream vulnerability information. We are therefore including a
fix for this flaw and have rated it important security severity in the
event our continued investigation finds this issue to be exploitable.

Tavis Ormandy of the Google Security Team discovered a denial of
service bug in the OpenSSH sshd server. A remote attacker can send a
specially crafted SSH-1 request to the server causing sshd to consume
a large quantity of CPU resources. (CVE-2006-4924)

All users of openssh should upgrade to these updated packages, which
contain backported patches that resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000010.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/25");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-askpass-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-askpass-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-clients-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-clients-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openssh-server-3.9p1-8.RHEL4.17")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openssh-server-3.9p1-8.RHEL4.17")) flag++;


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
