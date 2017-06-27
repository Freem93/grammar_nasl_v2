#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0257. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64628);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-3451", "CVE-2012-5633");
  script_bugtraq_id(55628, 57874);
  script_osvdb_id(85722, 90079);
  script_xref(name:"RHSA", value:"2013:0257");

  script_name(english:"RHEL 4 / 5 / 6 : JBoss EAP (RHSA-2013:0257)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated apache-cxf package for JBoss Enterprise Application
Platform 5.2.0 that fixes two security issues is now available for Red
Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

JBoss Enterprise Application Platform is a platform for Java
applications, which integrates the JBoss Application Server with JBoss
Hibernate and JBoss Seam.

If web services were deployed using Apache CXF with the
WSS4JInInterceptor enabled to apply WS-Security processing, HTTP GET
requests to these services were always granted access, without
applying authentication checks. The URIMappingInterceptor is a legacy
mechanism for allowing REST-like access (via GET requests) to simple
SOAP services. A remote attacker could use this flaw to access the
REST-like interface of a simple SOAP service using GET requests that
bypass the security constraints applied by WSS4JInInterceptor. This
flaw was only exploitable if WSS4JInInterceptor was used to apply
WS-Security processing. Services that use WS-SecurityPolicy to apply
security were not affected. (CVE-2012-5633)

It was found that Apache CXF was vulnerable to SOAPAction spoofing
attacks under certain conditions. If web services were exposed via
Apache CXF that use a unique SOAPAction for each service operation,
then a remote attacker could perform SOAPAction spoofing to call a
forbidden operation if it accepts the same parameters as an allowed
operation. WS-Policy validation was performed against the operation
being invoked, and an attack must pass validation to be successful.
(CVE-2012-3451)

Note that the CVE-2012-3451 and CVE-2012-5633 issues only affected
environments that have JBoss Web Services CXF installed.

Red Hat would like to thank the Apache CXF project for reporting
CVE-2012-3451.

Warning: Before applying this update, back up your existing JBoss
Enterprise Application Platform installation (including all
applications and configuration files).

All users of JBoss Enterprise Application Platform 5.2.0 on Red Hat
Enterprise Linux 4, 5, and 6 are advised to upgrade to this updated
package. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5633.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cxf.apache.org/security-advisories.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0257.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache-cxf package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");
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
  rhsa = "RHSA-2013:0257";
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

  if (! (rpm_exists(release:"RHEL4", rpm:"jbossws-") || rpm_exists(release:"RHEL5", rpm:"jbossws-") || rpm_exists(release:"RHEL6", rpm:"jbossws-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL4", reference:"apache-cxf-2.2.12-10.patch_06.ep5.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"apache-cxf-2.2.12-10.patch_06.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.2.12-10.patch_06.ep5.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-cxf");
  }
}
