#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60758);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-0590", "CVE-2009-2409", "CVE-2009-3555");

  script_name(english:"Scientific Linux Security Update : openssl on SL3.x, SL4.x i386/x86_64");
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
"A flaw was found in the way the TLS/SSL (Transport Layer
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

Dan Kaminsky found that browsers could accept certificates with MD2
hash signatures, even though MD2 is no longer considered a
cryptographically strong algorithm. This could make it easier for an
attacker to create a malicious certificate that would be treated as
trusted by a browser. OpenSSL now disables the use of the MD2
algorithm inside signatures by default. (CVE-2009-2409)

An input validation flaw was found in the handling of the BMPString
and UniversalString ASN1 string types in OpenSSL's
ASN1_STRING_print_ex() function. An attacker could use this flaw to
create a specially crafted X.509 certificate that could cause
applications using the affected function to crash when printing
certificate contents. (CVE-2009-0590)

For the update to take effect, all services linked to the OpenSSL
library must be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-20491"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=2100
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a738781"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssl, openssl-devel and / or openssl-perl
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(119, 310);

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
if (rpm_check(release:"SL3", reference:"openssl-0.9.7a-33.26")) flag++;
if (rpm_check(release:"SL3", reference:"openssl-devel-0.9.7a-33.26")) flag++;
if (rpm_check(release:"SL3", reference:"openssl-perl-0.9.7a-33.26")) flag++;

if (rpm_check(release:"SL4", reference:"openssl-0.9.7a-43.17.el4_8.5")) flag++;
if (rpm_check(release:"SL4", reference:"openssl-devel-0.9.7a-43.17.el4_8.5")) flag++;
if (rpm_check(release:"SL4", reference:"openssl-perl-0.9.7a-43.17.el4_8.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
