#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0741. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91073);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2015-5352", "CVE-2015-6563", "CVE-2015-6564", "CVE-2016-1908");
  script_osvdb_id(124008, 126030, 126033, 132941);
  script_xref(name:"RHSA", value:"2016:0741");

  script_name(english:"RHEL 6 : openssh (RHSA-2016:0741)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openssh is now available for Red Hat Enterprise Linux 6.

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
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-6563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-6564.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1908.html"
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfcf474c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0741.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0741";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-askpass-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-askpass-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-askpass-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-clients-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-clients-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-clients-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openssh-debuginfo-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-ldap-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-ldap-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-ldap-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-server-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-server-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-server-5.3p1-117.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pam_ssh_agent_auth-0.9.3-117.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-debuginfo / etc");
  }
}
