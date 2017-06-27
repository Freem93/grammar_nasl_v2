#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(91041);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2842");

  script_name(english:"Scientific Linux Security Update : openssl on SL7.x x86_64");
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
"Security Fix(es) :

  - A flaw was found in the way OpenSSL encoded certain
    ASN.1 data structures. An attacker could use this flaw
    to create a specially crafted certificate which, when
    verified or re-encoded by OpenSSL, could cause it to
    crash, or execute arbitrary code using the permissions
    of the user running an application compiled against the
    OpenSSL library. (CVE-2016-2108)

  - Two integer overflow flaws, leading to buffer overflows,
    were found in the way the EVP_EncodeUpdate() and
    EVP_EncryptUpdate() functions of OpenSSL parsed very
    large amounts of input data. A remote attacker could use
    these flaws to crash an application using OpenSSL or,
    possibly, execute arbitrary code with the permissions of
    the user running that application. (CVE-2016-2105,
    CVE-2016-2106)

  - It was discovered that OpenSSL leaked timing information
    when decrypting TLS/SSL and DTLS protocol encrypted
    records when the connection used the AES CBC cipher
    suite and the server supported AES-NI. A remote attacker
    could possibly use this flaw to retrieve plain text from
    encrypted packets by using a TLS/SSL or DTLS server as a
    padding oracle. (CVE-2016-2107)

  - Several flaws were found in the way BIO_*printf
    functions were implemented in OpenSSL. Applications
    which passed large amounts of untrusted data through
    these functions could crash or potentially execute code
    with the permissions of the user running such an
    application. (CVE-2016-0799, CVE-2016-2842)

  - A denial of service flaw was found in the way OpenSSL
    parsed certain ASN.1-encoded data from BIO (OpenSSL's
    I/O abstraction) inputs. An application using OpenSSL
    that accepts untrusted ASN.1 BIO input could be forced
    to allocate an excessive amount of data. (CVE-2016-2109)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1605&L=scientific-linux-errata&F=&S=&P=778
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?807a924f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/11");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-1.0.1e-51.el7_2.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1e-51.el7_2.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-51.el7_2.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-51.el7_2.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-51.el7_2.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-51.el7_2.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
