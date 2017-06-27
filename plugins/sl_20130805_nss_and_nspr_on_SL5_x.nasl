#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(69223);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/08/06 10:47:07 $");

  script_cve_id("CVE-2013-0791", "CVE-2013-1620");

  script_name(english:"Scientific Linux Security Update : nss and nspr on SL5.x i386/x86_64");
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
"It was discovered that NSS leaked timing information when decrypting
TLS/SSL and DTLS protocol encrypted records when CBC-mode cipher
suites were used. A remote attacker could possibly use this flaw to
retrieve plain text from the encrypted packets by using a TLS/SSL or
DTLS server as a padding oracle. (CVE-2013-1620)

An out-of-bounds memory read flaw was found in the way NSS decoded
certain certificates. If an application using NSS decoded a malformed
certificate, it could cause the application to crash. (CVE-2013-0791)

This update also fixes the following bugs :

  - A defect in the FreeBL library implementation of the
    Diffie-Hellman (DH) protocol previously caused Openswan
    to drop connections.

  - A memory leak in the nssutil_ReadSecmodDB() function has
    been fixed.

In addition, the nss package has been upgraded to upstream version
3.14.3, and the nspr package has been upgraded to upstream version
4.9.5. These updates provide a number of bug fixes and enhancements
over the previous versions.

Note that while upstream NSS version 3.14 prevents the use of
certificates that have an MD5 signature, this erratum includes a patch
that allows such certificates by default. To prevent the use of
certificates that have an MD5 signature, set the
'NSS_HASH_ALG_SUPPORT' environment variable to '-MD5'.

After installing this update, applications using NSS or NSPR must be
restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1308&L=scientific-linux-errata&T=0&P=77
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06eeabef"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"nspr-4.9.5-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-debuginfo-4.9.5-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.9.5-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.14.3-6.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.14.3-6.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.14.3-6.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.14.3-6.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.14.3-6.el5_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
