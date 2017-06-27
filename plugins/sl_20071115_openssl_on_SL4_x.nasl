#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60307);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-3108", "CVE-2007-5135");

  script_name(english:"Scientific Linux Security Update : openssl on SL4.x i386/x86_64");
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
"A flaw was found in the SSL_get_shared_ciphers() utility function. An
attacker could send a list of ciphers to an application that used this
function and overrun a buffer by a single byte (CVE-2007-5135). Few
applications make use of this vulnerable function and generally it is
used only when applications are compiled for debugging.

A number of possible side-channel attacks were discovered affecting
OpenSSL. A local attacker could possibly obtain RSA private keys being
used on a system. In practice these attacks would be difficult to
perform outside of a lab environment. This update contains backported
patches to mitigate these issues. (CVE-2007-3108)

As well, these updated packages fix the following bugs :

  - multithreaded applications could cause a segmentation
    fault or deadlock when calling the random number
    generator initialization (RAND_poll) in the OpenSSL
    library, for a large number of threads simultaneously.

  - in certain circumstances, if an application using the
    OpenSSL library reused the SSL session cache for
    multiple purposes (with various parameters of the SSL
    protocol), the session parameters could be mismatched.

  - a segmentation fault could occur when a corrupted pkcs12
    file was being loaded using the 'openssl pkcs12 -in
    [pkcs12-file]' command, where [pkcs12-file] is the
    pkcs12 file."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=3491
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?674a2059"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssl, openssl-devel and / or openssl-perl
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"openssl-0.9.7a-43.17.1")) flag++;
if (rpm_check(release:"SL4", reference:"openssl-devel-0.9.7a-43.17.1")) flag++;
if (rpm_check(release:"SL4", reference:"openssl-perl-0.9.7a-43.17.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
