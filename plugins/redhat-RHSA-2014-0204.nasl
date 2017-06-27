#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0204. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72678);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 15:40:56 $");

  script_cve_id("CVE-2014-0058");
  script_bugtraq_id(65762);
  script_xref(name:"RHSA", value:"2014:0204");

  script_name(english:"RHEL 5 / 6 : JBoss EAP (RHSA-2014:0204)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Red Hat JBoss Enterprise Application Platform 6.2.1 packages
that fix one security issue are now available for Red Hat Enterprise
Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having Low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

It was found that the security audit functionality, as provided by Red
Hat JBoss Enterprise Application Platform 6, logged request parameters
in plain text. This may have caused passwords to be included in the
audit log files when using BASIC or FORM-based authentication. A local
attacker with access to audit log files could possibly use this flaw
to obtain application or server authentication credentials.
(CVE-2014-0058)

The provided patch to fix CVE-2014-0058 also allows greater control
over which of the following components of web requests are captured in
audit logs :

  - parameters - cookies - headers - attributes

It is also possible to selectively mask some elements of headers,
parameters, cookies, and attributes using masks. This capability is
provided by two system properties, which are introduced by this 
patch :

1) org.jboss.security.web.audit

Description: This property controls the granularity of the security
auditing of web requests.

Possible values: off = Disables auditing of web requests headers =
Audits only the headers of web requests cookies = Audits only the
cookies of web requests parameters = Audits only the parameters of web
requests attributes = Audits only the attributes of web requests
headers,cookies,parameters = Audits the headers, cookies, and
parameters of web requests headers,cookies = Audits the headers and
cookies of web requests

Default Value: headers, parameters

Examples: Setting 'org.jboss.security.web.audit=off' disables security
auditing of web requests entirely. Setting
'org.jboss.security.web.audit=headers' enables security auditing of
only headers in web requests.

2) org.jboss.security.web.audit.mask

Description: This property can be used to specify a list of strings to
be matched against headers, parameters, cookies, and attributes of web
requests. Any element matching the specified masks will be excluded
from security audit logging.

Possible values: Any comma separated string indicating keys of
headers, parameters, cookies, and attributes.

Default Value: j_password, authorization

Note that currently the matching of the masks is fuzzy rather than
strict. For example, a mask of 'authorization' will mask both the
header called authorization and the parameter called
'custom_authorization'. A future release may introduce strict masks.

Warning: Before applying this update, back up your existing Red Hat
JBoss Enterprise Application Platform installation and deployed
applications.

All users of Red Hat JBoss Enterprise Application Platform 6.2.1 on
Red Hat Enterprise Linux 5 and 6 are advised to upgrade to these
updated packages. The JBoss server process must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0058.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0204.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jboss-as-web package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0204";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jboss-as-web") || rpm_exists(release:"RHEL6", rpm:"jboss-as-web"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"jboss-as-web-7.3.1-4.Final_redhat_4.1.ep6.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"jboss-as-web-7.3.1-4.Final_redhat_4.1.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jboss-as-web");
  }
}
