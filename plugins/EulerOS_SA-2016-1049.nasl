#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99812);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2014-7810",
    "CVE-2015-5346",
    "CVE-2016-5388",
    "CVE-2016-5425",
    "CVE-2016-6325"
  );
  script_bugtraq_id(
    74665
  );
  script_osvdb_id(
    122158,
    134827,
    141670,
    145333,
    145546
  );

  script_name(english:"EulerOS 2.0 SP1 : tomcat (EulerOS-SA-2016-1049)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tomcat packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The Expression Language (EL) implementation in Apache
    Tomcat 6.x before 6.0.44, 7.x before 7.0.58, and 8.x
    before 8.0.16 does not properly consider the
    possibility of an accessible interface implemented by
    an inaccessible class, which allows attackers to bypass
    a SecurityManager protection mechanism via a web
    application that leverages use of incorrect privileges
    during EL evaluation.(CVE-2014-7810)

  - Session fixation vulnerability in Apache Tomcat 7.x
    before 7.0.66, 8.x before 8.0.30, and 9.x before
    9.0.0.M2, when different session settings are used for
    deployments of multiple versions of the same web
    application, might allow remote attackers to hijack web
    sessions by leveraging use of a requestedSessionSSL
    field for an unintended request, related to
    CoyoteAdapter.java and Request.java.(CVE-2015-5346)

  - Apache Tomcat through 8.5.4, when the CGI Servlet is
    enabled, follows RFC 3875 section 4.1.18 and therefore
    does not protect applications from the presence of
    untrusted client data in the HTTP_PROXY environment
    variable, which might allow remote attackers to
    redirect an application's outbound HTTP traffic to an
    arbitrary proxy server via a crafted Proxy header in an
    HTTP request, aka an 'httpoxy' issue. NOTE: the vendor
    states 'A mitigation is planned for future releases of
    Tomcat, tracked as CVE-2016-5388'; in other words, this
    is not a CVE ID for a vulnerability.(CVE-2016-5388)

  - It was discovered that the Tomcat packages installed
    configuration file /usr/lib/tmpfiles.d/tomcat.conf
    writeable to the tomcat group. A member of the group or
    a malicious web application deployed on Tomcat could
    use this flaw to escalate their
    privileges.(CVE-2016-5425)

  - It was discovered that the Tomcat packages installed
    certain configuration files read by the Tomcat
    initialization script as writeable to the tomcat group.
    A member of the group or a malicious web application
    deployed on Tomcat could use this flaw to escalate
    their privileges.(CVE-2016-6325)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1049
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?670f4b1e");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:T/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["tomcat-7.0.54-8",
        "tomcat-admin-webapps-7.0.54-8",
        "tomcat-el-2.2-api-7.0.54-8",
        "tomcat-jsp-2.2-api-7.0.54-8",
        "tomcat-lib-7.0.54-8",
        "tomcat-servlet-3.0-api-7.0.54-8",
        "tomcat-webapps-7.0.54-8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");
}
