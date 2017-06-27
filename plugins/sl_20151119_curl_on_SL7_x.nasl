#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87554);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143", "CVE-2015-3148");

  script_name(english:"Scientific Linux Security Update : curl on SL7.x x86_64");
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
"It was found that the libcurl library did not correctly handle partial
literal IP addresses when parsing received HTTP cookies. An attacker
able to trick a user into connecting to a malicious server could use
this flaw to set the user's cookie to a crafted domain, making other
cookie-related issues easier to exploit. (CVE-2014-3613)

A flaw was found in the way the libcurl library performed the
duplication of connection handles. If an application set the
CURLOPT_COPYPOSTFIELDS option for a handle, using the handle's
duplicate could cause the application to crash or disclose a portion
of its memory. (CVE-2014-3707)

It was discovered that the libcurl library failed to properly handle
URLs with embedded end-of-line characters. An attacker able to make an
application using libcurl access a specially crafted URL via an HTTP
proxy could use this flaw to inject additional headers to the request
or construct additional requests. (CVE-2014-8150)

It was discovered that libcurl implemented aspects of the NTLM and
Negotatiate authentication incorrectly. If an application uses libcurl
and the affected mechanisms in a specifc way, certain requests to a
previously NTLM-authenticated server could appears as sent by the
wrong authenticated user. Additionally, the initial set of credentials
for HTTP Negotiate- authenticated requests could be reused in
subsequent requests, although a different set of credentials was
specified. (CVE-2015-3143, CVE-2015-3148)

Bug fixes :

  - An out-of-protocol fallback to SSL 3.0 was available
    with libcurl. Attackers could abuse the fallback to
    force downgrade of the SSL version. The fallback has
    been removed from libcurl. Users requiring this
    functionality can explicitly enable SSL 3.0 through the
    libcurl API.

  - TLS 1.1 and TLS 1.2 are no longer disabled by default in
    libcurl. You can explicitly disable them through the
    libcurl API.

  - FTP operations such as downloading files took a
    significantly long time to complete. Now, the FTP
    implementation in libcurl correctly sets blocking
    direction and estimated timeout for connections,
    resulting in faster FTP transfers.

Enhancements :

  - With the updated packages, it is possible to explicitly
    enable or disable new Advanced Encryption Standard (AES)
    cipher suites to be used for the TLS protocol.

  - The libcurl library did not implement a non-blocking SSL
    handshake, which negatively affected performance of
    applications based on the libcurl multi API. The
    non-blocking SSL handshake has been implemented in
    libcurl, and the libcurl multi API now immediately
    returns the control back to the application whenever it
    cannot read or write data from or to the underlying
    network socket.

  - The libcurl library used an unnecessarily long blocking
    delay for actions with no active file descriptors, even
    for short operations. Some actions, such as resolving a
    host name using /etc/hosts, took a long time to
    complete. The blocking code in libcurl has been modified
    so that the initial delay is short and gradually
    increases until an event occurs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=14587
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5978e139"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"curl-7.29.0-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"curl-debuginfo-7.29.0-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcurl-7.29.0-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcurl-devel-7.29.0-25.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");