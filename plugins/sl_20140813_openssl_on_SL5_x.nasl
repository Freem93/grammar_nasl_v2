#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(77215);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/28 19:00:57 $");

  script_cve_id("CVE-2014-0221", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3508", "CVE-2014-3510");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x i386/x86_64");
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
"It was discovered that the OBJ_obj2txt() function could fail to
properly NUL-terminate its output. This could possibly cause an
application using OpenSSL functions to format fields of X.509
certificates to disclose portions of its memory. (CVE-2014-3508)

Multiple flaws were discovered in the way OpenSSL handled DTLS
packets. A remote attacker could use these flaws to cause a DTLS
server or client using OpenSSL to crash or use excessive amounts of
memory. (CVE-2014-0221, CVE-2014-3505, CVE-2014-3506)

A NULL pointer dereference flaw was found in the way OpenSSL performed
a handshake when using the anonymous Diffie-Hellman (DH) key exchange.
A malicious server could cause a DTLS client using OpenSSL to crash if
that client had anonymous DH cipher suites enabled. (CVE-2014-3510)

For the update to take effect, all services linked to the OpenSSL
library (such as httpd and other SSL-enabled services) must be
restarted or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1408&L=scientific-linux-errata&T=0&P=1068
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55df76bc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"openssl-0.9.8e-27.el5_10.4")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-debuginfo-0.9.8e-27.el5_10.4")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8e-27.el5_10.4")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8e-27.el5_10.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
