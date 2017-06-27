#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2809 and 
# Oracle Linux Security Advisory ELSA-2016-2809 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95041);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/11/23 20:42:22 $");

  script_cve_id("CVE-2016-8638");
  script_osvdb_id(147544);
  script_xref(name:"RHSA", value:"2016:2809");

  script_name(english:"Oracle Linux 7 : ipsilon (ELSA-2016-2809)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2809 :

An update for ipsilon is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The ipsilon packages provide the Ipsilon identity provider service for
federated single sign-on (SSO). Ipsilon links authentication providers
and applications or utilities to allow for SSO. It includes a server
and utilities to configure Apache-based service providers.

Security Fix(es) :

* A vulnerability was found in ipsilon in the SAML2 provider's
handling of sessions. An attacker able to hit the logout URL could
determine what service providers other users are logged in to and
terminate their sessions. (CVE-2016-8638)

This issue was discovered by Patrick Uiterwijk (Red Hat) and Howard
Johnson."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006531.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ipsilon packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-authform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-authgssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-authldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-infosssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-persona");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-saml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-saml2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipsilon-tools-ipa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-authform-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-authgssapi-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-authldap-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-base-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-client-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-filesystem-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-infosssd-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-persona-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-saml2-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-saml2-base-1.0.0-13.el7_3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipsilon-tools-ipa-1.0.0-13.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipsilon / ipsilon-authform / ipsilon-authgssapi / ipsilon-authldap / etc");
}
