#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(79231);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/17 12:13:04 $");

  script_cve_id("CVE-2014-8564");

  script_name(english:"Scientific Linux Security Update : gnutls on SL7.x x86_64");
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
"An out-of-bounds memory write flaw was found in the way GnuTLS parsed
certain ECC (Elliptic Curve Cryptography) certificates or certificate
signing requests (CSR). A malicious user could create a specially
crafted ECC certificate or a certificate signing request that, when
processed by an application compiled against GnuTLS (for example,
certtool), could cause that application to crash or execute arbitrary
code with the permissions of the user running the application.
(CVE-2014-8564)

For the update to take effect, all applications linked to the GnuTLS
or libtasn1 library must be restarted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=2684
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36c566c5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-c++-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-dane-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-debuginfo-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-devel-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-utils-3.1.18-10.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
