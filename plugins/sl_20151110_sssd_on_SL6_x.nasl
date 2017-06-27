#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(86846);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/11 14:43:49 $");

  script_cve_id("CVE-2015-5292");

  script_name(english:"Scientific Linux Security Update : sssd on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that SSSD's Privilege Attribute Certificate (PAC)
responder plug-in would leak a small amount of memory on each
authentication request. A remote attacker could potentially use this
flaw to exhaust all available memory on the system by making repeated
requests to a Kerberized daemon application configured to authenticate
using the PAC responder plug-in. (CVE-2015-5292)

This update also fixes the following bugs :

  - Previously, SSSD did not correctly handle sudo rules
    that applied to groups with names containing special
    characters, such as the '(' opening parenthesis sign.
    Consequently, SSSD skipped such sudo rules. The internal
    sysdb search has been modified to escape special
    characters when searching for objects to which sudo
    rules apply. As a result, SSSD applies the described
    sudo rules as expected.

  - Prior to this update, SSSD did not correctly handle
    group names containing special Lightweight Directory
    Access Protocol (LDAP) characters, such as the '(' or
    ')' parenthesis signs. When a group name contained one
    or more such characters, the internal cache cleanup
    operation failed with an I/O error. With this update,
    LDAP special characters in the Distinguished Name (DN)
    of a cache entry are escaped before the cleanup
    operation starts. As a result, the cleanup operation
    completes successfully in the described situation.

  - Applications performing Kerberos authentication
    previously increased the memory footprint of the
    Kerberos plug-in that parses the Privilege Attribute
    Certificate (PAC) information. The plug-in has been
    updated to free the memory it allocates, thus fixing
    this bug.

  - Previously, when malformed POSIX attributes were defined
    in an Active Directory (AD) LDAP server, SSSD
    unexpectedly switched to offline mode. This update
    relaxes certain checks for AD POSIX attribute validity.
    As a result, SSSD now works as expected even when
    malformed POSIX attributes are present in AD and no
    longer enters offline mode in the described situation.

After installing the update, the sssd service will be restarted
automatically. Additionally, all running applications using the PAC
responder plug-in must be restarted for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1511&L=scientific-linux-errata&F=&S=&P=2022
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50a9ba9c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"libipa_hbac-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-python-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_nss_idmap-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_nss_idmap-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_nss_idmap-python-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_simpleifp-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_simpleifp-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"python-sssdconfig-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-ad-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-client-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-common-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-common-pac-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-dbus-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-debuginfo-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-ipa-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-krb5-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-krb5-common-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-ldap-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-proxy-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-tools-1.12.4-47.el6_7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
