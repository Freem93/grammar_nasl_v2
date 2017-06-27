#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(84015);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2015-4000");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x, SL7.x i386/x86_64 (Logjam)");
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
"A flaw was found in the way the TLS protocol composes the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them do decrypt all traffic.
(CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in OpenSSL
to reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Future updates may raise this limit
to 1024 bits.

For the update to take effect, all services linked to the OpenSSL
library must be restarted, or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=2853
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f81633cf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/04");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-30.el6_6.9")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-30.el6_6.9")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-30.el6_6.9")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-30.el6_6.9")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-30.el6_6.9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-1.0.1e-42.el7_1.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1e-42.el7_1.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-42.el7_1.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-42.el7_1.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-42.el7_1.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-42.el7_1.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
