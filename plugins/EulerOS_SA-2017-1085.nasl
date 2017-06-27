#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99951);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/03 13:42:52 $");

  script_cve_id(
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-8743"
  );
  script_osvdb_id(
    148286,
    148338,
    149054
  );

  script_name(english:"EulerOS 2.0 SP1 : httpd (EulerOS-SA-2017-1085)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - It was discovered that the mod_session_crypto module of
    httpd did not use any mechanisms to verify integrity of
    the encrypted session data stored in the user's
    browser. A remote attacker could use this flaw to
    decrypt and modify session data using a padding oracle
    attack. (CVE-2016-0736)

  - It was discovered that the mod_auth_digest module of
    httpd did not properly check for memory allocation
    failures. A remote attacker could use this flaw to
    cause httpd child processes to repeatedly crash if the
    server used HTTP digest authentication. (CVE-2016-2161)

  - It was discovered that the HTTP parser in httpd
    incorrectly allowed certain characters not permitted by
    the HTTP protocol specification to appear unencoded in
    HTTP request headers. If httpd was used in conjunction
    with a proxy or backend server that interpreted those
    characters differently, a remote attacker could
    possibly use this flaw to inject data into HTTP
    responses, resulting in proxy cache poisoning.
    (CVE-2016-8743)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1085
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d32c9963");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
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

pkgs = ["httpd-2.4.6-45.0.1.4.h2",
        "httpd-devel-2.4.6-45.0.1.4.h2",
        "httpd-manual-2.4.6-45.0.1.4.h2",
        "httpd-tools-2.4.6-45.0.1.4.h2",
        "mod_ssl-2.4.6-45.0.1.4.h2"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
