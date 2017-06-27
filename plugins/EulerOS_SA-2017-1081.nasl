#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99947);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/03 13:42:52 $");

  script_cve_id(
    "CVE-2016-6816",
    "CVE-2016-8745"
  );
  script_osvdb_id(
    147619,
    148477
  );

  script_name(english:"EulerOS 2.0 SP1 : tomcat (EulerOS-SA-2017-1081)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tomcat packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - It was discovered that the code that parsed the HTTP
    request line permitted invalid characters. This could
    be exploited, in conjunction with a proxy that also
    permitted the invalid characters but with a different
    interpretation, to inject data into the HTTP response.
    By manipulating the HTTP response the attacker could
    poison a web-cache, perform an XSS attack, or obtain
    sensitive information from requests other then their
    own. (CVE-2016-6816)

  - A bug was discovered in the error handling of the send
    file code for the NIO HTTP connector. This led to the
    current Processor object being added to the Processor
    cache multiple times allowing information leakage
    between requests including, and not limited to, session
    ID and the response body. (CVE-2016-8745)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1081
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0a72e6d");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");

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

pkgs = ["tomcat-7.0.69-11",
        "tomcat-admin-webapps-7.0.69-11",
        "tomcat-el-2.2-api-7.0.69-11",
        "tomcat-jsp-2.2-api-7.0.69-11",
        "tomcat-lib-7.0.69-11",
        "tomcat-servlet-3.0-api-7.0.69-11",
        "tomcat-webapps-7.0.69-11"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
