#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1069. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43834);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2005-2090", "CVE-2005-3510", "CVE-2006-3835", "CVE-2007-0450", "CVE-2007-1858", "CVE-2007-3382", "CVE-2007-3385");
  script_bugtraq_id(13873, 15325, 19106, 22960, 25316);
  script_xref(name:"RHSA", value:"2007:1069");

  script_name(english:"RHEL 3 / 4 : tomcat in Satellite Server (RHSA-2007:1069)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat packages that fix multiple security issues are now
available for Red Hat Network Satellite Server.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Tomcat is a servlet container for Java Servlet and JavaServer Pages
technologies.

It was reported Tomcat did not properly handle the following character
sequence in a cookie: \' (a backslash followed by a double-quote). It
was possible remote attackers could use this failure to obtain
sensitive information, such as session IDs, for session hijacking
attacks (CVE-2007-3385).

Tomcat was found treating single quote characters -- ' -- as
delimiters in cookies. This could allow remote attackers to obtain
sensitive information, such as session IDs, for session hijacking
attacks (CVE-2007-3382).

The default Tomcat configuration permitted the use of insecure SSL
cipher suites including the anonymous cipher suite. (CVE-2007-1858)

Tomcat permitted various characters as path delimiters. If Tomcat was
used behind certain proxies and configured to only proxy some
contexts, an attacker could construct an HTTP request to work around
the context restriction and potentially access non-proxied content.
(CVE-2007-0450)

Directory listings were enabled by default in Tomcat. Information
stored unprotected under the document root was visible to anyone if
the administrator did not disable directory listings. (CVE-2006-3835)

It was found that generating listings of large directories was CPU
intensive. An attacker could make repeated requests to obtain a
directory listing of any large directory, leading to a denial of
service. (CVE-2005-3510)

Tomcat was found to accept multiple content-length headers in a
request. This could allow attackers to poison a web-cache, bypass web
application firewall protection, or conduct cross-site scripting
attacks. (CVE-2005-2090)

Users should upgrade to these erratum packages which contain an update
to Tomcat that resolves these issues, and add the tyrex and
jakarta-commons-pool packages which are required dependencies of the
new Tomcat version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-3835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0450.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3382.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3385.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-5.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-1069.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected jakarta-commons-pool, tomcat5 and / or tyrex
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tyrex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:1069";
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

  if (! (rpm_exists(release:"RHEL3", rpm:"rhns-app-") || rpm_exists(release:"RHEL4", rpm:"rhns-app-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL3", reference:"jakarta-commons-pool-1.2-2jpp_2rh")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tomcat5-5.0.30-0jpp_6rh")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tyrex-1.0.1-2jpp_2rh")) flag++;

  if (rpm_check(release:"RHEL4", reference:"jakarta-commons-pool-1.2-2jpp_2rh")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tomcat5-5.0.30-0jpp_6rh")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tyrex-1.0.1-2jpp_2rh")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-pool / tomcat5 / tyrex");
  }
}
