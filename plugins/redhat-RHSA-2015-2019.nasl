#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2019. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86845);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-5292");
  script_osvdb_id(128895);
  script_xref(name:"RHSA", value:"2015:2019");

  script_name(english:"RHEL 6 : sssd (RHSA-2015:2019)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms. It also provides the Name Service Switch (NSS) and the
Pluggable Authentication Modules (PAM) interfaces toward the system,
and a pluggable back-end system to connect to multiple different
account sources.

It was found that SSSD's Privilege Attribute Certificate (PAC)
responder plug-in would leak a small amount of memory on each
authentication request. A remote attacker could potentially use this
flaw to exhaust all available memory on the system by making repeated
requests to a Kerberized daemon application configured to authenticate
using the PAC responder plug-in. (CVE-2015-5292)

This update also fixes the following bugs :

* Previously, SSSD did not correctly handle sudo rules that applied to
groups with names containing special characters, such as the '('
opening parenthesis sign. Consequently, SSSD skipped such sudo rules.
The internal sysdb search has been modified to escape special
characters when searching for objects to which sudo rules apply. As a
result, SSSD applies the described sudo rules as expected.
(BZ#1258398)

* Prior to this update, SSSD did not correctly handle group names
containing special Lightweight Directory Access Protocol (LDAP)
characters, such as the '(' or ')' parenthesis signs. When a group
name contained one or more such characters, the internal cache cleanup
operation failed with an I/O error. With this update, LDAP special
characters in the Distinguished Name (DN) of a cache entry are escaped
before the cleanup operation starts. As a result, the cleanup
operation completes successfully in the described situation.
(BZ#1264098)

* Applications performing Kerberos authentication previously increased
the memory footprint of the Kerberos plug-in that parses the Privilege
Attribute Certificate (PAC) information. The plug-in has been updated
to free the memory it allocates, thus fixing this bug. (BZ#1268783)

* Previously, when malformed POSIX attributes were defined in an
Active Directory (AD) LDAP server, SSSD unexpectedly switched to
offline mode. This update relaxes certain checks for AD POSIX
attribute validity. As a result, SSSD now works as expected even when
malformed POSIX attributes are present in AD and no longer enters
offline mode in the described situation. (BZ#1268784)

All sssd users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the sssd service will be restarted automatically.
Additionally, all running applications using the PAC responder plug-in
must be restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5292.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2019.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2019";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"libipa_hbac-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libipa_hbac-devel-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libipa_hbac-python-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libipa_hbac-python-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libipa_hbac-python-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsss_idmap-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsss_idmap-devel-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsss_nss_idmap-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsss_nss_idmap-devel-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libsss_nss_idmap-python-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libsss_nss_idmap-python-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsss_nss_idmap-python-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsss_simpleifp-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libsss_simpleifp-devel-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"python-sssdconfig-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-ad-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-ad-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-ad-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"sssd-client-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-common-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-common-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-common-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-common-pac-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-common-pac-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-common-pac-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-dbus-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-dbus-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-dbus-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"sssd-debuginfo-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-ipa-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-ipa-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-ipa-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-krb5-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-krb5-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-krb5-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-krb5-common-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-krb5-common-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-krb5-common-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-ldap-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-ldap-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-ldap-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-proxy-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-proxy-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-proxy-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-tools-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-tools-1.12.4-47.el6_7.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-tools-1.12.4-47.el6_7.4")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libipa_hbac-python / libsss_idmap / etc");
  }
}
