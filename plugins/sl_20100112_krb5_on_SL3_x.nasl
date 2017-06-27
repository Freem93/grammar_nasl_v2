#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60721);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:08 $");

  script_cve_id("CVE-2009-4212");

  script_name(english:"Scientific Linux Security Update : krb5 on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-4212 krb: KDC integer overflows in AES and RC4 decryption
routines (MITKRB5-SA-2009-004)

Multiple integer underflow flaws, leading to heap-based corruption,
were found in the way the MIT Kerberos Key Distribution Center (KDC)
decrypted ciphertexts encrypted with the Advanced Encryption Standard
(AES) and ARCFOUR (RC4) encryption algorithms. If a remote KDC client
were able to provide a specially crafted AES- or RC4-encrypted
ciphertext or texts, it could potentially lead to either a denial of
service of the central KDC (KDC crash or abort upon processing the
crafted ciphertext), or arbitrary code execution with the privileges
of the KDC (i.e., root privileges). (CVE-2009-4212)

All running services using the MIT Kerberos libraries must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1001&L=scientific-linux-errata&T=0&P=1065
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?def5ebdf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"krb5-devel-1.2.7-71")) flag++;
if (rpm_check(release:"SL3", reference:"krb5-libs-1.2.7-71")) flag++;
if (rpm_check(release:"SL3", reference:"krb5-server-1.2.7-71")) flag++;
if (rpm_check(release:"SL3", reference:"krb5-workstation-1.2.7-71")) flag++;

if (rpm_check(release:"SL4", reference:"krb5-devel-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-libs-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-server-1.3.4-62.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-workstation-1.3.4-62.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"krb5-devel-1.6.1-36.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-libs-1.6.1-36.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-1.6.1-36.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-workstation-1.6.1-36.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
