#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0066 and 
# CentOS Errata and Security Advisory 2015:0066 respectively.
#

include("compat.inc");

if (description)
{
  script_id(80867);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/06/21 04:38:55 $");

  script_cve_id(
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206"
  );
  script_bugtraq_id(
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942
  );
  script_osvdb_id(
    116790,
    116791,
    116792,
    116793,
    116794,
    116795,
    116796
  );
  script_xref(name:"RHSA", value:"2015:0066");

  script_name(english:"CentOS 6 / 7 : openssl (CESA-2015:0066)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL),
Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose
cryptography library.

  - A NULL pointer dereference flaw was found in the DTLS
    implementation of OpenSSL. A remote attacker could send
    a specially crafted DTLS message, which would cause an
    OpenSSL server to crash. (CVE-2014-3571)

  - A memory leak flaw was found in the way the
    dtls1_buffer_record() function of OpenSSL parsed certain
    DTLS messages. A remote attacker could send multiple
    specially crafted DTLS messages to exhaust all available
    memory of a DTLS server. (CVE-2015-0206)

  - It was found that OpenSSL's BigNumber Squaring
    implementation could produce incorrect results under
    certain special conditions. This flaw could possibly
    affect certain OpenSSL library functionality, such as
    RSA blinding. Note that this issue occurred rarely and
    with a low probability, and there is currently no known
    way of exploiting it. (CVE-2014-3570)

  - It was discovered that OpenSSL would perform an ECDH key
    exchange with a non-ephemeral key even when the
    ephemeral ECDH cipher suite was selected. A malicious
    server could make a TLS/SSL client using OpenSSL use a
    weaker key exchange method than the one requested by the
    user. (CVE-2014-3572)

  - It was discovered that OpenSSL would accept ephemeral
    RSA keys when using non-export RSA cipher suites. A
    malicious server could make a TLS/SSL client using
    OpenSSL use a weaker key exchange method.
    (CVE-2015-0204)

  - Multiple flaws were found in the way OpenSSL parsed
    X.509 certificates. An attacker could use these flaws to
    modify an X.509 certificate to produce a certificate
    with a different fingerprint without invalidating its
    signature, and possibly bypass fingerprint-based
    blacklisting in applications. (CVE-2014-8275)

  - It was found that an OpenSSL server would, under certain
    conditions, accept Diffie-Hellman client certificates
    without the use of a private key. An attacker could use
    a user's client certificate to authenticate as that
    user, without needing the private key. (CVE-2015-0205)

All OpenSSL users are advised to upgrade to these updated packages,
which contain a backported patch to mitigate the above issues. For the
update to take effect, all services linked to the OpenSSL library
(such as httpd and other SSL-enabled services) must be restarted or
the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-January/020885.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cba8b4b1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-January/020884.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d597301"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;

packages = make_list("openssl", "openssl-devel", "openssl-perl", "openssl-static");
advisory_version = "1.0.1e-30.el6_6.5";
buggy_branch = "1.0.1e-30.el6\.([89]|\d{2,})\|";
foreach currpackage (packages)
{
  rpm_regex = currpackage + "-" + buggy_branch;
  advisory_reference = currpackage + "-" + advisory_version;
  if (! rpm_exists(release:"CentOS-6", rpm:rpm_regex) && rpm_check(release:"CentOS-6", reference:advisory_reference)) flag++;
}

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-static-1.0.1e-34.el7_0.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
