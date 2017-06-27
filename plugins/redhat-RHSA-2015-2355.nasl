#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2355. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86983);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-5292");
  script_osvdb_id(128895);
  script_xref(name:"RHSA", value:"2015:2355");

  script_name(english:"RHEL 7 : sssd (RHSA-2015:2355)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix one security issue, multiple bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms.

It was found that SSSD's Privilege Attribute Certificate (PAC)
responder plug-in would leak a small amount of memory on each
authentication request. A remote attacker could potentially use this
flaw to exhaust all available memory on the system by making repeated
requests to a Kerberized daemon application configured to authenticate
using the PAC responder plug-in. (CVE-2015-5292)

The sssd packages have been upgraded to upstream version 1.13.0, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#1205554)

Several enhancements are described in the Red Hat Enterprise Linux 7.2
Release Notes, linked to in the References section :

* SSSD smart card support (BZ#854396) * Cache authentication in SSSD
(BZ#910187) * SSSD supports overriding automatically discovered AD
site (BZ#1163806) * SSSD can now deny SSH access to locked accounts
(BZ#1175760) * SSSD enables UID and GID mapping on individual clients
(BZ#1183747) * Background refresh of cached entries (BZ#1199533) *
Multi-step prompting for one-time and long-term passwords (BZ#1200873)
* Caching for initgroups operations (BZ#1206575)

Bugs fixed :

* When the SELinux user content on an IdM server was set to an empty
string, the SSSD SELinux evaluation utility returned an error.
(BZ#1192314)

* If the ldap_child process failed to initialize credentials and
exited with an error multiple times, operations that create files in
some cases started failing due to an insufficient amount of i-nodes.
(BZ#1198477)

* The SRV queries used a hard-coded TTL timeout, and environments that
wanted the SRV queries to be valid for a certain time only were
blocked. Now, SSSD parses the TTL value out of the DNS packet.
(BZ#1199541)

* Previously, initgroups operation took an excessive amount of time.
Now, logins and ID processing are faster for setups with AD back end
and disabled ID mapping. (BZ#1201840)

* When an IdM client with Red Hat Enterprise Linux 7.1 or later was
connecting to a server with Red Hat Enterprise Linux 7.0 or earlier,
authentication with an AD trusted domain caused the sssd_be process to
terminate unexpectedly. (BZ#1202170)

* If replication conflict entries appeared during HBAC processing, the
user was denied access. Now, the replication conflict entries are
skipped and users are permitted access. (BZ#1202245)

* The array of SIDs no longer contains an uninitialized value and SSSD
no longer crashes. (BZ#1204203)

* SSSD supports GPOs from different domain controllers and no longer
crashes when processing GPOs from different domain controllers.
(BZ#1205852)

* SSSD could not refresh sudo rules that contained groups with special
characters, such as parentheses, in their name. (BZ#1208507)

* The IPA names are not qualified on the client side if the server
already qualified them, and IdM group members resolve even if
default_domain_suffix is used on the server side. (BZ#1211830)

* The internal cache cleanup task has been disabled by default to
improve performance of the sssd_be process. (BZ#1212489)

* Now, default_domain_suffix is not considered anymore for autofs
maps. (BZ#1216285)

* The user can set subdomain_inherit=ignore_group-members to disable
fetching group members for trusted domains. (BZ#1217350)

* The group resolution failed with an error message: 'Error: 14 (Bad
address)'. The binary GUID handling has been fixed. (BZ#1226119)

Enhancements added :

* The description of default_domain_suffix has been improved in the
manual pages. (BZ#1185536)

* With the new '%0' template option, users on SSSD IdM clients can now
use home directories set on AD. (BZ#1187103)

All sssd users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5292.html"
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4086253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2355.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sss-murmur");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2355";
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
  if (rpm_check(release:"RHEL7", reference:"libipa_hbac-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libipa_hbac-devel-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libsss_idmap-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libsss_idmap-devel-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libsss_nss_idmap-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libsss_nss_idmap-devel-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libsss_simpleifp-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libsss_simpleifp-devel-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-libipa_hbac-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-libipa_hbac-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-libsss_nss_idmap-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-libsss_nss_idmap-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-sss-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-sss-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-sss-murmur-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-sss-murmur-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-sssdconfig-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-ad-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-ad-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"sssd-client-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"sssd-common-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-common-pac-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-common-pac-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-dbus-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-dbus-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"sssd-debuginfo-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-ipa-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-ipa-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-krb5-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-krb5-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"sssd-krb5-common-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-ldap-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-ldap-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-libwbclient-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-libwbclient-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"sssd-libwbclient-devel-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-proxy-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-proxy-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sssd-tools-1.13.0-40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sssd-tools-1.13.0-40.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_idmap / libsss_idmap-devel / etc");
  }
}
