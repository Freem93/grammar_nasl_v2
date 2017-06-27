#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0964. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27052);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2007-3108", "CVE-2007-4995", "CVE-2007-5135");
  script_bugtraq_id(25831);
  script_osvdb_id(29262, 37055, 37895);
  script_xref(name:"RHSA", value:"2007:0964");

  script_name(english:"RHEL 5 : openssl (RHSA-2007:0964)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that correct several security issues are now
available for Red Hat Enterprise 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength general purpose cryptography library. Datagram TLS
(DTLS) is a protocol based on TLS that is capable of securing datagram
transport (UDP for instance).

The OpenSSL security team discovered a flaw in DTLS support. An
attacker could create a malicious client or server that could trigger
a heap overflow. This is possibly exploitable to run arbitrary code,
but it has not been verified (CVE-2007-4995). Note that this flaw only
affects applications making use of DTLS. Red Hat does not ship any
DTLS client or server applications in Red Hat Enterprise Linux.

A flaw was found in the SSL_get_shared_ciphers() utility function. An
attacker could send a list of ciphers to an application that used this
function and overrun a buffer with a single byte (CVE-2007-5135). Few
applications make use of this vulnerable function and generally it is
used only when applications are compiled for debugging.

A number of possible side-channel attacks were discovered affecting
OpenSSL. A local attacker could possibly obtain RSA private keys being
used on a system. In practice these attacks would be difficult to
perform outside of a lab environment. This update contains backported
patches designed to mitigate these issues. (CVE-2007-3108).

Users of OpenSSL should upgrade to these updated packages, which
contain backported patches to resolve these issues.

Please note that the fix for the DTLS flaw involved an overhaul of the
DTLS handshake processing which may introduce incompatibilities if a
new client is used with an older server.

After installing this update, users are advised to either restart all
services that use OpenSSL or restart their system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3108.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5135.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20071012.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0964.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssl, openssl-devel and / or openssl-perl
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0964";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL5", reference:"openssl-0.9.8b-8.3.el5_0.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"openssl-devel-0.9.8b-8.3.el5_0.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssl-perl-0.9.8b-8.3.el5_0.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssl-perl-0.9.8b-8.3.el5_0.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssl-perl-0.9.8b-8.3.el5_0.2")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl");
  }
}
