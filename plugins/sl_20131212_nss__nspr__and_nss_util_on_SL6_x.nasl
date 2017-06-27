#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71424);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/14 15:19:53 $");

  script_cve_id("CVE-2013-1620", "CVE-2013-1739", "CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607");

  script_name(english:"Scientific Linux Security Update : nss, nspr, and nss-util on SL6.x i386/x86_64");
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
"A flaw was found in the way NSS handled invalid handshake packets. A
remote attacker could use this flaw to cause a TLS/SSL client using
NSS to crash or, possibly, execute arbitrary code with the privileges
of the user running the application. (CVE-2013-5605)

It was found that the fix for CVE-2013-1620 released via
SLSA-2013:1135 introduced a regression causing NSS to read
uninitialized data when a decryption failure occurred. A remote
attacker could use this flaw to cause a TLS/SSL server using NSS to
crash. (CVE-2013-1739)

An integer overflow flaw was discovered in both NSS and NSPR's
implementation of certification parsing on 64-bit systems. A remote
attacker could use these flaws to cause an application using NSS or
NSPR to crash. (CVE-2013-1741, CVE-2013-5607)

It was discovered that NSS did not reject certificates with
incompatible key usage constraints when validating them while the
verifyLog feature was enabled. An application using the NSS
certificate validation API could accept an invalid certificate.
(CVE-2013-5606)

After installing this update, applications using NSS, NSPR, or
nss-util must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=4641
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8de3049"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");
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
if (rpm_check(release:"SL6", reference:"nspr-4.10.2-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-debuginfo-4.10.2-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-devel-4.10.2-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.15.3-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.15.3-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.15.3-1.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
