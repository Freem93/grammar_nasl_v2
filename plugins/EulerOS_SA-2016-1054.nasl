#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99816);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2015-5174",
    "CVE-2015-5345",
    "CVE-2015-5351",
    "CVE-2016-0706",
    "CVE-2016-0714",
    "CVE-2016-0763",
    "CVE-2016-3092"
  );
  script_osvdb_id(
    134823,
    134824,
    134825,
    134826,
    134828,
    134829,
    140354
  );

  script_name(english:"EulerOS 2.0 SP1 : tomcat (EulerOS-SA-2016-1054)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tomcat packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Directory traversal vulnerability in RequestUtil.java
    in Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.65,
    and 8.x before 8.0.27 allows remote authenticated users
    to bypass intended SecurityManager restrictions and
    list a parent directory via a /.. (slash dot dot) in a
    pathname used by a web application in a getResource,
    getResourceAsStream, or getResourcePaths call, as
    demonstrated by the $CATALINA_BASE/webapps
    directory.(CVE-2015-5174)

  - The Mapper component in Apache Tomcat 6.x before
    6.0.45, 7.x before 7.0.68, 8.x before 8.0.30, and 9.x
    before 9.0.0.M2 processes redirects before considering
    security constraints and Filters, which allows remote
    attackers to determine the existence of a directory via
    a URL that lacks a trailing / (slash)
    character.(CVE-2015-5345)

  - The (1) Manager and (2) Host Manager applications in
    Apache Tomcat 7.x before 7.0.68, 8.x before 8.0.31, and
    9.x before 9.0.0.M2 establish sessions and send CSRF
    tokens for arbitrary new requests, which allows remote
    attackers to bypass a CSRF protection mechanism by
    using a token.(CVE-2015-5351)

  - Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.68, 8.x
    before 8.0.31, and 9.x before 9.0.0.M2 does not place
    org.apache.catalina.manager.StatusManagerServlet on the
    org/apache/catalina/core/RestrictedServlets.properties
    list, which allows remote authenticated users to bypass
    intended SecurityManager restrictions and read
    arbitrary HTTP requests, and consequently discover
    session ID values, via a crafted web
    application.(CVE-2016-0706)

  - The session-persistence implementation in Apache Tomcat
    6.x before 6.0.45, 7.x before 7.0.68, 8.x before
    8.0.31, and 9.x before 9.0.0.M2 mishandles session
    attributes, which allows remote authenticated users to
    bypass intended SecurityManager restrictions and
    execute arbitrary code in a privileged context via a
    web application that places a crafted object in a
    session.(CVE-2016-0714)

  - The setGlobalContext method in
    org/apache/naming/factory/ResourceLinkFactory.java in
    Apache Tomcat 7.x before 7.0.68, 8.x before 8.0.31, and
    9.x before 9.0.0.M3 does not consider whether
    ResourceLinkFactory.setGlobalContext callers are
    authorized, which allows remote authenticated users to
    bypass intended SecurityManager restrictions and read
    or write to arbitrary application data, or cause a
    denial of service (application disruption), via a web
    application that sets a crafted global
    context.(CVE-2016-0763)

  - The MultipartStream class in Apache Commons Fileupload
    before 1.3.2, as used in Apache Tomcat 7.x before
    7.0.70, 8.x before 8.0.36, 8.5.x before 8.5.3, and 9.x
    before 9.0.0.M7 and other products, allows remote
    attackers to cause a denial of service (CPU
    consumption) via a long boundary string.(CVE-2016-3092)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1054
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23e980e7");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
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

pkgs = ["tomcat-7.0.69-10",
        "tomcat-admin-webapps-7.0.69-10",
        "tomcat-el-2.2-api-7.0.69-10",
        "tomcat-jsp-2.2-api-7.0.69-10",
        "tomcat-lib-7.0.69-10",
        "tomcat-servlet-3.0-api-7.0.69-10",
        "tomcat-webapps-7.0.69-10"];

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
