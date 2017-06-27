#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99836);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/03 13:48:59 $");

  script_cve_id(
    "CVE-2016-3119",
    "CVE-2016-3120"
  );
  script_osvdb_id(
    136224,
    142164
  );
  script_xref(name:"IAVB", value:"2016-B-0115");

  script_name(english:"EulerOS 2.0 SP1 : krb5 (EulerOS-SA-2016-1076)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the krb5 packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A NULL pointer dereference flaw was found in MIT
    Kerberos kadmind service. An authenticated attacker
    with permission to modify a principal entry could use
    this flaw to cause kadmind to dereference a NULL
    pointer and crash by supplying an empty DB argument to
    the modify_principal command, if kadmind was configured
    to use the LDAP KDB module. (CVE-2016-3119)

  - A NULL pointer dereference flaw was found in MIT
    Kerberos krb5kdc service. An authenticated attacker
    could use this flaw to cause krb5kdc to dereference a
    NULL pointer and crash by making an S4U2Self request,
    if the restrict_anonymous_to_tgt option was set to
    true.(CVE-2016-3120)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1076
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfb7adce");
  script_set_attribute(attribute:"solution", value:
"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

pkgs = ["krb5-devel-1.13.2-12.h2",
        "krb5-libs-1.13.2-12.h2",
        "krb5-pkinit-1.13.2-12.h2",
        "krb5-server-1.13.2-12.h2",
        "krb5-server-ldap-1.13.2-12.h2",
        "krb5-workstation-1.13.2-12.h2"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
