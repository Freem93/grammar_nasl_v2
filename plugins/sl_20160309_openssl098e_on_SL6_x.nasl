#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(89825);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0800");

  script_name(english:"Scientific Linux Security Update : openssl098e on SL6.x, SL7.x i386/x86_64 (DROWN)");
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
"A padding oracle flaw was found in the Secure Sockets Layer version
2.0 (SSLv2) protocol. An attacker can potentially use this flaw to
decrypt RSA-encrypted cipher text from a connection using a newer
SSL/TLS protocol version, allowing them to decrypt such connections.
This cross-protocol attack is publicly referred to as DROWN.
(CVE-2016-0800)

It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2
connection handshakes that indicated non-zero clear key length for
non- export cipher suites. An attacker could use this flaw to decrypt
recorded SSLv2 sessions with the server by using it as a decryption
oracle.(CVE-2016-0703)

It was discovered that the SSLv2 protocol implementation in OpenSSL
did not properly implement the Bleichenbacher protection for export
cipher suites. An attacker could use a SSLv2 server using OpenSSL as a
Bleichenbacher oracle. (CVE-2016-0704)

Note: The CVE-2016-0703 and CVE-2016-0704 issues could allow for more
efficient exploitation of the CVE-2016-0800 issue via the DROWN
attack.

A denial of service flaw was found in the way OpenSSL handled SSLv2
handshake messages. A remote attacker could use this flaw to cause a
TLS/SSL server using OpenSSL to exit on a failed assertion if it had
both the SSLv2 protocol and EXPORT-grade cipher suites enabled.
(CVE-2015-0293)

A flaw was found in the way malicious SSLv2 clients could negotiate
SSLv2 ciphers that have been disabled on the server. This could result
in weak SSLv2 ciphers being used for SSLv2 connections, making them
vulnerable to man-in-the-middle attacks. (CVE-2015-3197)

For the update to take effect, all services linked to the openssl098e
library must be restarted, or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1603&L=scientific-linux-errata&F=&S=&P=3432
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?349846cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssl098e and / or openssl098e-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssl098e-0.9.8e-20.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"openssl098e-debuginfo-0.9.8e-20.el6_7.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl098e-0.9.8e-29.el7_2.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl098e-debuginfo-0.9.8e-29.el7_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
