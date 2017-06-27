#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0741 and 
# Oracle Linux Security Advisory ELSA-2016-0741 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91148);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2015-5352", "CVE-2015-6563", "CVE-2015-6564", "CVE-2016-1908");
  script_osvdb_id(124008, 126030, 126033, 132941);
  script_xref(name:"RHSA", value:"2016:0741");

  script_name(english:"Oracle Linux 6 : openssh (ELSA-2016-0741)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0741 :

An update for openssh is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenSSH is an SSH protocol implementation supported by a number of
Linux, UNIX, and similar operating systems. It includes the core files
necessary for both the OpenSSH client and server.

Security Fix(es) :

* It was found that the OpenSSH client did not properly enforce the
ForwardX11Timeout setting. A malicious or compromised remote X
application could possibly use this flaw to establish a trusted
connection to the local X server, even if only untrusted X11
forwarding was requested. (CVE-2015-5352)

* A flaw was found in the way OpenSSH handled PAM authentication when
using privilege separation. An attacker with valid credentials on the
system and able to fully compromise a non-privileged
pre-authentication process using a different flaw could use this flaw
to authenticate as other users. (CVE-2015-6563)

* A use-after-free flaw was found in OpenSSH. An attacker able to
fully compromise a non-privileged pre-authentication process using a
different flaw could possibly cause sshd to crash or execute arbitrary
code with root privileges. (CVE-2015-6564)

* An access flaw was discovered in OpenSSH; the OpenSSH client did not
correctly handle failures to generate authentication cookies for
untrusted X11 forwarding. A malicious or compromised remote X
application could possibly use this flaw to establish a trusted
connection to the local X server, even if only untrusted X11
forwarding was requested. (CVE-2016-1908)

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.8 Release Notes and Red Hat Enterprise Linux 6.8
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-May/006054.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"openssh-5.3p1-117.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-askpass-5.3p1-117.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-clients-5.3p1-117.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-ldap-5.3p1-117.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-server-5.3p1-117.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pam_ssh_agent_auth-0.9.3-117.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-ldap / etc");
}
