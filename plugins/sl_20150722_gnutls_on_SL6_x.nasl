#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85193);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");

  script_name(english:"Scientific Linux Security Update : gnutls on SL6.x i386/x86_64");
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
"It was found that GnuTLS did not check activation and expiration dates
of CA certificates. This could cause an application using GnuTLS to
incorrectly accept a certificate as valid when its issuing CA is
already expired. (CVE-2014-8155)

It was found that GnuTLS did not verify whether a hashing algorithm
listed in a signature matched the hashing algorithm listed in the
certificate. An attacker could create a certificate that used a
different hashing algorithm than it claimed, possibly causing GnuTLS
to use an insecure, disallowed hashing algorithm during certificate
verification. (CVE-2015-0282)

It was discovered that GnuTLS did not check if all sections of X.509
certificates indicate the same signature algorithm. This flaw, in
combination with a different flaw, could possibly lead to a bypass of
the certificate signature check. (CVE-2015-0294)

The CVE-2014-8155 issue was discovered by Marcel Kolaja of Red Hat.
The CVE-2015-0282 and CVE-2015-0294 issues were discovered by Nikos
Mavrogiannopoulos of the Red Hat Security Technologies Team.

This update also fixes the following bug :

  - Previously, under certain circumstances, the certtool
    utility could generate X.509 certificates which
    contained a negative modulus. Consequently, such
    certificates could have interoperation problems with the
    software using them. The bug has been fixed, and
    certtool no longer generates X.509 certificates
    containing a negative modulus."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=1412
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79c875b8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
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
if (rpm_check(release:"SL6", reference:"gnutls-2.8.5-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-debuginfo-2.8.5-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-devel-2.8.5-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-guile-2.8.5-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-utils-2.8.5-18.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
