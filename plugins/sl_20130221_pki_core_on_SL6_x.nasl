#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64958);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/01 11:58:42 $");

  script_cve_id("CVE-2012-4543");

  script_name(english:"Scientific Linux Security Update : pki-core on SL6.x i386/x86_64");
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
"Note: The Certificate Authority component provided by this advisory
cannot be used as a standalone server. It is installed and operates as
a part of Identity Management (the IPA component) in Scientific Linux.

Multiple cross-site scripting flaws were discovered in Certificate
System. An attacker could use these flaws to perform a cross-site
scripting (XSS) attack against victims using Certificate System's web
interface. (CVE-2012-4543)

This update also fixes the following bugs :

  - Previously, due to incorrect conversion of large
    integers while generating a new serial number, some of
    the most significant bits in the serial number were
    truncated. Consequently, the serial number generated for
    certificates was sometimes smaller than expected and
    this incorrect conversion in turn led to a collision if
    a certificate with the smaller number already existed in
    the database. This update removes the incorrect integer
    conversion so that no serial numbers are truncated. As a
    result, the installation wizard proceeds as expected.

  - The certificate authority used a different profile for
    issuing the audit certificate than it used for renewing
    it. The issuing profile was for two years, and the
    renewal was for six months. They should both be for two
    years. This update sets the default and constraint
    parameters in the caSignedLogCert.cfg audit certificate
    renewal profile to two years.

This update also adds the following enhancements :

  - IPA (Identity, Policy and Audit) now provides an
    improved way to determine that PKI is up and ready to
    service requests. Checking the service status was not
    sufficient. This update creates a mechanism for clients
    to determine that the PKI subsystem is up using the
    getStatus() function to query the cs.startup_state in
    CS.cfg.

  - This update increases the default root CA validity
    period from eight years to twenty years."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=4035
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abe1a0b5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
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
if (rpm_check(release:"SL6", reference:"pki-ca-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-common-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-common-javadoc-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-core-debuginfo-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-java-tools-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-java-tools-javadoc-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-native-tools-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-selinux-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-setup-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-silent-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-symkey-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-util-9.0.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-util-javadoc-9.0.3-30.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
