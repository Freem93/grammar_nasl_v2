#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1940. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93763);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/10 20:46:32 $");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-6302", "CVE-2016-6304", "CVE-2016-6306");
  script_osvdb_id(139313, 139471, 142095, 143021, 143259, 143309, 143389, 144687, 144688);
  script_xref(name:"RHSA", value:"2016:1940");

  script_name(english:"RHEL 6 / 7 : openssl (RHSA-2016:1940)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openssl is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL)
and Transport Layer Security (TLS) protocols, as well as a
full-strength general-purpose cryptography library.

Security Fix(es) :

* A memory leak flaw was found in the way OpenSSL handled TLS status
request extension data during session renegotiation. A remote attacker
could cause a TLS server using OpenSSL to consume an excessive amount
of memory and, possibly, exit unexpectedly after exhausting all
available memory, if it enabled OCSP stapling support. (CVE-2016-6304)

* It was discovered that OpenSSL did not always use constant time
operations when computing Digital Signature Algorithm (DSA)
signatures. A local attacker could possibly use this flaw to obtain a
private DSA key belonging to another user or service running on the
same system. (CVE-2016-2178)

* It was discovered that the Datagram TLS (DTLS) implementation could
fail to release memory in certain cases. A malicious DTLS client could
cause a DTLS server using OpenSSL to consume an excessive amount of
memory and, possibly, exit unexpectedly after exhausting all available
memory. (CVE-2016-2179)

* A flaw was found in the Datagram TLS (DTLS) replay protection
implementation in OpenSSL. A remote attacker could possibly use this
flaw to make a DTLS server using OpenSSL to reject further packets
sent from a DTLS client over an established DTLS connection.
(CVE-2016-2181)

* An out of bounds write flaw was discovered in the OpenSSL
BN_bn2dec() function. An attacker able to make an application using
OpenSSL to process a large BIGNUM could cause the application to crash
or, possibly, execute arbitrary code. (CVE-2016-2182)

* A flaw was found in the DES/3DES cipher was used as part of the
TLS/SSL protocol. A man-in-the-middle attacker could use this flaw to
recover some plaintext data by capturing large amounts of encrypted
traffic between TLS/SSL server and client if the communication used a
DES/3DES based ciphersuite. (CVE-2016-2183)

This update mitigates the CVE-2016-2183 issue by lowering priority of
DES cipher suites so they are not preferred over cipher suites using
AES. For compatibility reasons, DES cipher suites remain enabled by
default and included in the set of cipher suites identified by the
HIGH cipher string. Future updates may move them to MEDIUM or not
enable them by default.

* An integer underflow flaw leading to a buffer over-read was found in
the way OpenSSL parsed TLS session tickets. A remote attacker could
use this flaw to crash a TLS server using OpenSSL if it used SHA-512
as HMAC for session tickets. (CVE-2016-6302)

* Multiple integer overflow flaws were found in the way OpenSSL
performed pointer arithmetic. A remote attacker could possibly use
these flaws to cause a TLS/SSL server or client using OpenSSL to
crash. (CVE-2016-2177)

* An out of bounds read flaw was found in the way OpenSSL formatted
Public Key Infrastructure Time-Stamp Protocol data for printing. An
attacker could possibly cause an application using OpenSSL to crash if
it printed time stamp data from the attacker. (CVE-2016-2180)

* Multiple out of bounds read flaws were found in the way OpenSSL
handled certain TLS/SSL protocol handshake messages. A remote attacker
could possibly use these flaws to crash a TLS/SSL server or client
using OpenSSL. (CVE-2016-6306)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2016-6304 and CVE-2016-6306 and OpenVPN for reporting
CVE-2016-2183. Upstream acknowledges Shi Lei (Gear Team of Qihoo 360
Inc.) as the original reporter of CVE-2016-6304 and CVE-2016-6306; and
Karthikeyan Bhargavan (Inria) and Gaetan Leurent (Inria) as the
original reporters of CVE-2016-2183."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-6302.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-6304.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-6306.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20160922.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1940.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2016:1940";
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
  if (rpm_check(release:"RHEL6", reference:"openssl-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-debuginfo-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-devel-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-perl-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-perl-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-perl-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-static-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-static-1.0.1e-48.el6_8.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-static-1.0.1e-48.el6_8.3")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssl-1.0.1e-51.el7_2.7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssl-1.0.1e-51.el7_2.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-debuginfo-1.0.1e-51.el7_2.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-devel-1.0.1e-51.el7_2.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-libs-1.0.1e-51.el7_2.7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssl-perl-1.0.1e-51.el7_2.7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-51.el7_2.7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-static-1.0.1e-51.el7_2.7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-libs / etc");
  }
}
