#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0066. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80879);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_bugtraq_id(71936);
  script_osvdb_id(116790, 116791, 116792, 116793, 116794, 116795, 116796);
  script_xref(name:"RHSA", value:"2015:0066");

  script_name(english:"RHEL 6 / 7 : openssl (RHSA-2015:0066) (FREAK)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL),
Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose
cryptography library.

A NULL pointer dereference flaw was found in the DTLS implementation
of OpenSSL. A remote attacker could send a specially crafted DTLS
message, which would cause an OpenSSL server to crash. (CVE-2014-3571)

A memory leak flaw was found in the way the dtls1_buffer_record()
function of OpenSSL parsed certain DTLS messages. A remote attacker
could send multiple specially crafted DTLS messages to exhaust all
available memory of a DTLS server. (CVE-2015-0206)

It was found that OpenSSL's BigNumber Squaring implementation could
produce incorrect results under certain special conditions. This flaw
could possibly affect certain OpenSSL library functionality, such as
RSA blinding. Note that this issue occurred rarely and with a low
probability, and there is currently no known way of exploiting it.
(CVE-2014-3570)

It was discovered that OpenSSL would perform an ECDH key exchange with
a non-ephemeral key even when the ephemeral ECDH cipher suite was
selected. A malicious server could make a TLS/SSL client using OpenSSL
use a weaker key exchange method than the one requested by the user.
(CVE-2014-3572)

It was discovered that OpenSSL would accept ephemeral RSA keys when
using non-export RSA cipher suites. A malicious server could make a
TLS/SSL client using OpenSSL use a weaker key exchange method.
(CVE-2015-0204)

Multiple flaws were found in the way OpenSSL parsed X.509
certificates. An attacker could use these flaws to modify an X.509
certificate to produce a certificate with a different fingerprint
without invalidating its signature, and possibly bypass
fingerprint-based blacklisting in applications. (CVE-2014-8275)

It was found that an OpenSSL server would, under certain conditions,
accept Diffie-Hellman client certificates without the use of a private
key. An attacker could use a user's client certificate to authenticate
as that user, without needing the private key. (CVE-2015-0205)

All OpenSSL users are advised to upgrade to these updated packages,
which contain a backported patch to mitigate the above issues. For the
update to take effect, all services linked to the OpenSSL library
(such as httpd and other SSL-enabled services) must be restarted or
the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8275.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0205.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20150108.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0066.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0066";
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
  if (rpm_check(release:"RHEL6", reference:"openssl-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-debuginfo-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-devel-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-perl-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-perl-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-perl-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-static-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-static-1.0.1e-30.el6.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-static-1.0.1e-30.el6.5")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssl-1.0.1e-34.el7_0.7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssl-1.0.1e-34.el7_0.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-debuginfo-1.0.1e-34.el7_0.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-devel-1.0.1e-34.el7_0.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-libs-1.0.1e-34.el7_0.7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssl-perl-1.0.1e-34.el7_0.7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-34.el7_0.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-static-1.0.1e-34.el7_0.7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-libs / etc");
  }
}
