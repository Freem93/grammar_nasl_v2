#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0677. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54599);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-0014");
  script_bugtraq_id(46264);
  script_osvdb_id(70847);
  script_xref(name:"RHSA", value:"2011:0677");

  script_name(english:"RHEL 6 : openssl (RHSA-2011:0677)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix one security issue, two bugs, and
add two enhancements are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A buffer over-read flaw was discovered in the way OpenSSL parsed the
Certificate Status Request TLS extensions in ClientHello TLS handshake
messages. A remote attacker could possibly use this flaw to crash an
SSL server using the affected OpenSSL functionality. (CVE-2011-0014)

This update fixes the following bugs :

* The 'openssl speed' command (which provides algorithm speed
measurement) failed when openssl was running in FIPS (Federal
Information Processing Standards) mode, even if testing of FIPS
approved algorithms was requested. FIPS mode disables ciphers and
cryptographic hash algorithms that are not approved by the NIST
(National Institute of Standards and Technology) standards. With this
update, the 'openssl speed' command no longer fails. (BZ#619762)

* The 'openssl pkcs12 -export' command failed to export a PKCS#12 file
in FIPS mode. The default algorithm for encrypting a certificate in
the PKCS#12 file was not FIPS approved and thus did not work. The
command now uses a FIPS approved algorithm by default in FIPS mode.
(BZ#673453)

This update also adds the following enhancements :

* The 'openssl s_server' command, which previously accepted
connections only over IPv4, now accepts connections over IPv6.
(BZ#601612)

* For the purpose of allowing certain maintenance commands to be run
(such as 'rsync'), an 'OPENSSL_FIPS_NON_APPROVED_MD5_ALLOW'
environment variable has been added. When a system is configured for
FIPS mode and is in a maintenance state, this newly added environment
variable can be set to allow software that requires the use of an MD5
cryptographic hash algorithm to be run, even though the hash algorithm
is not approved by the FIPS-140-2 standard. (BZ#673071)

Users of OpenSSL are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues and add these
enhancements. For the update to take effect, all services linked to
the OpenSSL library must be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0677.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:0677";
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
  if (rpm_check(release:"RHEL6", reference:"openssl-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openssl-debuginfo-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openssl-devel-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-perl-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-perl-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-perl-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-static-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-static-1.0.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-static-1.0.0-10.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
  }
}
