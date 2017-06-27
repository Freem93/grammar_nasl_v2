#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60513);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-5077");

  script_name(english:"Scientific Linux Security Update : openssl on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"The Google security team discovered a flaw in the way OpenSSL checked
the verification of certificates. An attacker in control of a
malicious server, or able to effect a 'man in the middle' attack,
could present a malformed SSL/TLS signature from a certificate chain
to a vulnerable client and bypass validation. (CVE-2008-5077)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0901&L=scientific-linux-errata&T=0&P=456
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7630a71"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
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
if (rpm_check(release:"SL3", reference:"openssl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"SL3", reference:"openssl-devel-0.9.7a-33.25")) flag++;
if (rpm_check(release:"SL3", reference:"openssl-perl-0.9.7a-33.25")) flag++;
if (rpm_check(release:"SL3", reference:"openssl096b-0.9.6b-16.49")) flag++;

if (rpm_check(release:"SL4", reference:"openssl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"openssl-devel-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"openssl-perl-0.9.7a-43.17.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"openssl096b-0.9.6b-22.46.el4_7")) flag++;

if (rpm_check(release:"SL5", reference:"openssl-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8b-10.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl097a-0.9.7a-9.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
