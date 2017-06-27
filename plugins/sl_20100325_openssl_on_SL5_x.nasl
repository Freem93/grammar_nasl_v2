#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60759);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-3245", "CVE-2009-3555", "CVE-2010-0433");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x i386/x86_64");
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
"CVE-2009-3555 TLS: MITM attacks via session renegotiation

CVE-2010-0433 openssl: crash caused by a missing
krb5_sname_to_principal() return value check

CVE-2009-3245 openssl: missing bn_wexpand return value checks

It was discovered that OpenSSL did not always check the return value
of the bn_wexpand() function. An attacker able to trigger a memory
allocation failure in that function could cause an application using
the OpenSSL library to crash or, possibly, execute arbitrary code.
(CVE-2009-3245)

A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handled session
renegotiation. A man-in-the-middle attacker could use this flaw to
prefix arbitrary plain text to a client's session (for example, an
HTTPS connection to a website). This could force the server to process
an attacker's request as if authenticated using the victim's
credentials. This update addresses this flaw by implementing the TLS
Renegotiation Indication Extension, as defined in RFC 5746.
(CVE-2009-3555)

Refer to the following Knowledgebase article for additional details
about the CVE-2009-3555 flaw:
http://kbase.redhat.com/faq/docs/DOC-20491

A missing return value check flaw was discovered in OpenSSL, that
could possibly cause OpenSSL to call a Kerberos library function with
invalid arguments, resulting in a NULL pointer dereference crash in
the MIT Kerberos library. In certain configurations, a remote attacker
could use this flaw to crash a TLS/SSL server using OpenSSL by
requesting Kerberos cipher suites during the TLS handshake.
(CVE-2010-0433)

For the update to take effect, all services linked to the OpenSSL
library must be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-20491"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=2231
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54ec60ef"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssl, openssl-devel and / or openssl-perl
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"openssl-0.9.8e-12.el5_4.6")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8e-12.el5_4.6")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8e-12.el5_4.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
