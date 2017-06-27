#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0532 and 
# Oracle Linux Security Advisory ELSA-2016-0532 respectively.
#

include("compat.inc");

if (description)
{
  script_id(90295);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2015-8629", "CVE-2015-8630", "CVE-2015-8631");
  script_osvdb_id(133808, 133831, 133882);
  script_xref(name:"RHSA", value:"2016:0532");

  script_name(english:"Oracle Linux 7 : krb5 (ELSA-2016-0532)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0532 :

An update for krb5 is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kerberos is a network authentication system, which can improve the
security of your network by eliminating the insecure practice of
sending passwords over the network in unencrypted form. It allows
clients and servers to authenticate to each other with the help of a
trusted third party, the Kerberos key distribution center (KDC).

Security Fix(es) :

* A memory leak flaw was found in the krb5_unparse_name() function of
the MIT Kerberos kadmind service. An authenticated attacker could
repeatedly send specially crafted requests to the server, which could
cause the server to consume large amounts of memory resources,
ultimately leading to a denial of service due to memory exhaustion.
(CVE-2015-8631)

* An out-of-bounds read flaw was found in the kadmind service of MIT
Kerberos. An authenticated attacker could send a maliciously crafted
message to force kadmind to read beyond the end of allocated memory,
and write the memory contents to the KDC database if the attacker has
write permission, leading to information disclosure. (CVE-2015-8629)

* A NULL pointer dereference flaw was found in the procedure used by
the MIT Kerberos kadmind service to store policies: the
kadm5_create_principal_3() and kadm5_modify_principal() function did
not ensure that a policy was given when KADM5_POLICY was set. An
authenticated attacker with permissions to modify the database could
use this flaw to add or modify a principal with a policy set to NULL,
causing the kadmind service to crash. (CVE-2015-8630)

The CVE-2015-8631 issue was discovered by Simo Sorce of Red Hat."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005916.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-devel-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-libs-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-pkinit-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-server-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-server-ldap-1.13.2-12.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-workstation-1.13.2-12.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-pkinit / krb5-server / etc");
}
