#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99859);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/02 13:34:09 $");

  script_cve_id(
    "CVE-2016-7030",
    "CVE-2016-9575"
  );
  script_osvdb_id(
    148787,
    148788
  );

  script_name(english:"EulerOS 2.0 SP1 : ipa (EulerOS-SA-2017-1013)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ipa packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - It was discovered that the default IdM password
    policies that lock out accounts after a certain number
    of failed login attempts were also applied to host and
    service accounts. A remote unauthenticated user could
    use this flaw to cause a denial of service attack
    against kerberized services. (CVE-2016-7030)

  - It was found that IdM's certprofile-mod command did not
    properly check the user's permissions while modifying
    certificate profiles. An authenticated, unprivileged
    attacker could use this flaw to modify profiles to
    issue certificates with arbitrary naming or key usage
    information and subsequently use such certificates for
    other attacks. (CVE-2016-9575)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aba8635");
  script_set_attribute(attribute:"solution", value:
"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-server-trust-ad");
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

pkgs = ["ipa-admintools-4.2.0-15.0.1.19.h1",
        "ipa-client-4.2.0-15.0.1.19.h1",
        "ipa-python-4.2.0-15.0.1.19.h1",
        "ipa-server-4.2.0-15.0.1.19.h1",
        "ipa-server-trust-ad-4.2.0-15.0.1.19.h1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa");
}
