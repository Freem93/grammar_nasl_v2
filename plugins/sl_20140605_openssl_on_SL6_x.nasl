#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(74350);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/13 15:30:40 $");

  script_cve_id("CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x i386/x86_64");
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
"It was found that OpenSSL clients and servers could be forced, via a
specially crafted handshake packet, to use weak keying material for
communication. A man-in-the-middle attacker could use this flaw to
decrypt and modify traffic between a client and a server.
(CVE-2014-0224)

Note: In order to exploit this flaw, both the server and the client
must be using a vulnerable version of OpenSSL; the server must be
using OpenSSL version 1.0.1 and above, and the client must be using
any version of OpenSSL. For more information about this flaw, refer 
to :

A buffer overflow flaw was found in the way OpenSSL handled invalid
DTLS packet fragments. A remote attacker could possibly use this flaw
to execute arbitrary code on a DTLS client or server. (CVE-2014-0195)

Multiple flaws were found in the way OpenSSL handled read and write
buffers when the SSL_MODE_RELEASE_BUFFERS mode was enabled. A TLS/SSL
client or server using OpenSSL could crash or unexpectedly drop
connections when processing certain SSL traffic. (CVE-2010-5298,
CVE-2014-0198)

A denial of service flaw was found in the way OpenSSL handled certain
DTLS ServerHello requests. A specially crafted DTLS handshake packet
could cause a DTLS client using OpenSSL to crash. (CVE-2014-0221)

A NULL pointer dereference flaw was found in the way OpenSSL performed
anonymous Elliptic Curve Diffie Hellman (ECDH) key exchange. A
specially crafted handshake packet could cause a TLS/SSL client that
has the anonymous ECDH cipher suite enabled to crash. (CVE-2014-3470)

For the update to take effect, all services linked to the OpenSSL
library (such as httpd and other SSL-enabled services) must be
restarted or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1406&L=scientific-linux-errata&T=0&P=953
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33892d79"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-16.el6_5.14")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-16.el6_5.14")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-16.el6_5.14")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-16.el6_5.14")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-16.el6_5.14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
