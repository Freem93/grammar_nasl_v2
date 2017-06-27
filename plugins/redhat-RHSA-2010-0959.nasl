#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0959. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63963);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/04 15:51:49 $");

  script_cve_id("CVE-2010-3862");
  script_osvdb_id(70267);
  script_xref(name:"RHSA", value:"2010:0959");

  script_name(english:"RHEL 4 : JBoss EAP (RHSA-2010:0959)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform 5.1 packages that fix
one security issue and various bugs are now available for Red Hat
Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

JBoss Enterprise Application Platform is the market leading platform
for innovative and scalable Java applications; integrating the JBoss
Application Server, with JBoss Hibernate and JBoss Seam into a
complete, simple enterprise solution.

A flaw was found in the JBoss Remoting component. A remote attacker
could use specially crafted input to cause the JBoss Remoting
listeners to become unresponsive, resulting in a denial of service
condition for services communicating via JBoss Remoting sockets.
(CVE-2010-3862)

Red Hat would like to thank Ole Husgaard of eXerp.com for reporting
this issue.

These updated packages include multiple bug fixes. Documentation for
these bug fixes will be available shortly from the Release Notes,
linked to in the References section.

As well, this update adds a new jbossws-cxf package to JBoss
Enterprise Application Platform 5.1.0, to provide the sources for
jbossws-cxf. (BZ#644403)

Warning: Before applying this update, please backup the JBoss
Enterprise Application Platform 'jboss-as/server/$PROFILE/deploy/'
directory, along with all other customized configuration files.

All users of JBoss Enterprise Application Platform 5.0 on Red Hat
Enterprise Linux 4 are advised to upgrade to these updated packages.
The JBoss server process must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3862.html"
  );
  # http://docs.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/5/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f390cc27"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0959.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-security-policy-cc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-embedded");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0959";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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

  if (! (rpm_exists(release:"RHEL4", rpm:"jbossas-remoting-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL4", reference:"jboss-remoting-2.5.3-5.SP1.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-security-policy-cc-5.1.0-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-cxf-3.1.2-4.SP7.6.jdk6.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jopr-embedded-1.3.4-16.SP1.7.ep5.el4")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jboss-remoting / jbossas-security-policy-cc / jbossws-cxf / etc");
  }
}
