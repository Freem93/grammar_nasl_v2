#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1052 and 
# Oracle Linux Security Advisory ELSA-2014-1052 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77191);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/12/01 17:25:14 $");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511");
  script_bugtraq_id(69075, 69076, 69078, 69079, 69081, 69082, 69084);
  script_xref(name:"RHSA", value:"2014:1052");

  script_name(english:"Oracle Linux 6 / 7 : openssl (ELSA-2014-1052)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1052 :

Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL),
Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose
cryptography library.

A race condition was found in the way OpenSSL handled ServerHello
messages with an included Supported EC Point Format extension. A
malicious server could possibly use this flaw to cause a
multi-threaded TLS/SSL client using OpenSSL to write into freed
memory, causing the client to crash or execute arbitrary code.
(CVE-2014-3509)

It was discovered that the OBJ_obj2txt() function could fail to
properly NUL-terminate its output. This could possibly cause an
application using OpenSSL functions to format fields of X.509
certificates to disclose portions of its memory. (CVE-2014-3508)

A flaw was found in the way OpenSSL handled fragmented handshake
packets. A man-in-the-middle attacker could use this flaw to force a
TLS/SSL server using OpenSSL to use TLS 1.0, even if both the client
and the server supported newer protocol versions. (CVE-2014-3511)

Multiple flaws were discovered in the way OpenSSL handled DTLS
packets. A remote attacker could use these flaws to cause a DTLS
server or client using OpenSSL to crash or use excessive amounts of
memory. (CVE-2014-3505, CVE-2014-3506, CVE-2014-3507)

A NULL pointer dereference flaw was found in the way OpenSSL performed
a handshake when using the anonymous Diffie-Hellman (DH) key exchange.
A malicious server could cause a DTLS client using OpenSSL to crash if
that client had anonymous DH cipher suites enabled. (CVE-2014-3510)

All OpenSSL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library
(such as httpd and other SSL-enabled services) must be restarted or
the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-August/004361.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-August/004362.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"openssl-1.0.1e-16.el6_5.15")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-devel-1.0.1e-16.el6_5.15")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-perl-1.0.1e-16.el6_5.15")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-static-1.0.1e-16.el6_5.15")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-1.0.1e-34.el7_0.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-34.el7_0.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-34.el7_0.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-34.el7_0.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-34.el7_0.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-libs / openssl-perl / etc");
}
