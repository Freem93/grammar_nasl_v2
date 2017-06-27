#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0069.
#

include("compat.inc");

if (description)
{
  script_id(91749);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2011-1024", "CVE-2013-4449", "CVE-2015-6908");
  script_bugtraq_id(46363, 63190);
  script_osvdb_id(72528, 98656, 127342);

  script_name(english:"OracleVM 3.2 : openldap (OVMSA-2016-0069)");
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
    vulnerability (#1263170)

  - fix: syncprov psearch race condition (#999811)

  - fix: CVE-2013-4449 segfault on certain queries with rwm
    overlay (#1064146)

  - fix: do not send IPv6 DNS queries when IPv6 is disabled
    on the host (#812772)

  - fix: disable static libraries stripping (#684630)

  - fix: memory leaks in syncrepl and slap_sl_free (#741184)

  - new feature update: honor priority/weight with
    ldap_domain2hostlist (#733435)

  - fix: initscript marked as %config incorrectly (#738768)

  - new feature: honor priority/weight with
    ldap_domain2hostlist (#733435)

  - fix: strict aliasing warnings during package build
    (#732381)

  - fix: OpenLDAP packages lack debug data (#684630)

  - doc: Document preferred use of TLS_CACERT instead of
    TLS_CACERTDIR to specify Certificate Authorities
    (#699652)

  - fix: libldap ignores a directory of CA certificates if
    any of them can't be read (#609722)

  - fix: Migration: migrate_all_offline.sh can't handle
    duplicate entries (#563148)

  - fix: Init script is working wrong if database recovery
    is needed (#604092)

  - fix: CVE-2011-1024 ppolicy forwarded bind failure
    messages cause success (#680486)

  - fix: slapd concurrent access to connections causes slapd
    to silently die (#641953)

  - backport: ldap_init_fd API function

  - fix: ppolicy crash while replace-deleting userPassword
    attribute (#665951)

  - fix: connection freeze when using TLS (#591419)

  - don't remove task twice during replication

  - fixed segfault issues in modrdn (#606375)

  - added patch handling null char in TLS to compat package
    (#606375, patch backported by Jan Vcelak )"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000489.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"openldap-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"OVS3.2", reference:"openldap-clients-2.3.43-29.el5_11")) flag++;

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
