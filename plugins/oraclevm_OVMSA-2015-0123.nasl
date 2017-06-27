#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0123.
#

include("compat.inc");

if (description)
{
  script_id(86216);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-6908");
  script_osvdb_id(127342);

  script_name(english:"OracleVM 3.3 : openldap (OVMSA-2015-0123)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - CVE-2015-6908 openldap: ber_get_next denial of service
    vulnerability (#1263171)

  - fix: nslcd segfaults due to incorrect mutex
    initialization (#1144294)

  - fix: Updating openldap deletes database if slapd.conf is
    used (#1193519)

  - fix: ppc64: slaptest segfault in openldap-2.4.40
    (#1202696)

  - fix: bring back accidentaly removed patch (#1147983)

  - rebase to 2.4.40 (#1147983)

  - fix: make /etc/openldap/check_password.conf readable by
    ldap (#1155390)

  - revert previous patch (#1172296)

  - fix: crash in ldap_domain2hostlist when processing SRV
    record (#1164369)

  - support TLS 1.1 and later (#1160467)

  - enhancement: add ppolicy-check-password (#1155390)

  - fix: prevent freed memory reuse (#1172296)

  - fix: provide a shim libldif.so (#1110382)

  - fix: remove correct tmp file when generating server cert
    (#1102083)

  - remove unapplied patches

  - fix: TLS_REQCERT documentation in client manpage
    (#1027796)

  - review %configure and remove nonexistent options

  - add another missing patch forgotten during the rebase

  - fix: enable dynamic linking - unresolved symbols in the
    smbk5pwd module

  - add missing patches that were removed by mistake during
    the rebase

  - rebase to 2.4.39 (#923680)

  + drop a lot of upstreamed patches, backport the rest

  + compile in mdb

  + remove automatic slapd.conf -> slapd-config conversion

  - fix: segfault on certain queries with rwm overlay
    (#1003038)

  - fix: deadlock during SSL_ForceHandshake (#996373)

  + revert nss-handshake-threadsafe.patch"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-September/000371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06953aae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap / openldap-clients packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"openldap-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"openldap-clients-2.4.40-6.el6_7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients");
}
