#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61320);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2012-0884", "CVE-2012-2333");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x, SL6.x i386/x86_64");
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
"An integer underflow flaw, leading to a buffer over-read, was found in
the way OpenSSL handled DTLS (Datagram Transport Layer Security)
application data record lengths when using a block cipher in CBC
(cipher-blockchaining) mode. A malicious DTLS client or server could
use this flaw to crash its DTLS connection peer. (CVE-2012-2333)

On SL6 this update also fixes an uninitialized variable use bug,
introduced by the fix for CVE-2012-0884. This bug could possibly cause
an attempt to create an encrypted message in the CMS (Cryptographic
Message Syntax) format to fail. For the update to take effect all
services linked to the OpenSSL library must be restarted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1205&L=scientific-linux-errata&T=0&P=1747
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4def7f4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/29");
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
if (rpm_check(release:"SL5", reference:"openssl-0.9.8e-22.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8e-22.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8e-22.el5_8.4")) flag++;

if (rpm_check(release:"SL6", reference:"openssl-1.0.0-20.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.0-20.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.0-20.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.0-20.el6_2.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
