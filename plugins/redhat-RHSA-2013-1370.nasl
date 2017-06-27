#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1370. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70371);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-4210");
  script_bugtraq_id(62721);
  script_osvdb_id(97951);
  script_xref(name:"RHSA", value:"2013:1370");

  script_name(english:"RHEL 4 / 5 / 6 : jboss-remoting in JBoss EWP (RHSA-2013:1370)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated jboss-remoting package that fixes one security issue is now
available for Red Hat JBoss Web Platform 5.2.0 for Red Hat Enterprise
Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

JBoss Remoting is a framework for building distributed applications in
Java.

A denial of service flaw was found in the implementation of the
org.jboss.remoting.transport.socket.ServerThread class in JBoss
Remoting. An attacker could use this flaw to exhaust all available
file descriptors on the target server, preventing legitimate
connections. Note that to exploit this flaw remotely, the remoting
port must be exposed directly or indirectly (for example, deploying a
public facing application that uses JBoss Remoting could indirectly
expose this flaw). (CVE-2013-4210)

This issue was discovered by James Livingston of the Red Hat Support
Engineering Group.

Warning: Before applying this update, back up your existing Red Hat
JBoss Web Platform installation (including all applications and
configuration files).

All users of Red Hat JBoss Web Platform 5.2.0 on Red Hat Enterprise
Linux 4, 5, and 6 are advised to upgrade to this updated package. The
JBoss server process must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4210.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1370.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jboss-remoting package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:1370";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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

  if (! (rpm_exists(release:"RHEL4", rpm:"jboss-seam2-") || rpm_exists(release:"RHEL5", rpm:"jboss-seam2-") || rpm_exists(release:"RHEL6", rpm:"jboss-seam2-")) || rpm_exists(rpm:"jbossas-welcome-content-eap")) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EWP");

  if (rpm_check(release:"RHEL4", reference:"jboss-remoting-2.5.4-11.SP4_patch01.ep5.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.5.4-11.SP4_patch01.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"jboss-remoting-2.5.4-11.SP4_patch01.ep5.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jboss-remoting");
  }
}
