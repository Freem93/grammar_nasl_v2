#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(97295);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2016-8610", "CVE-2017-3731");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x, SL7.x i386/x86_64");
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

  - An integer underflow leading to an out of bounds read
    flaw was found in OpenSSL. A remote attacker could
    possibly use this flaw to crash a 32-bit TLS/SSL server
    or client using OpenSSL if it used the RC4-MD5 cipher
    suite. (CVE-2017-3731)

  - A denial of service flaw was found in the way the
    TLS/SSL protocol defined processing of ALERT packets
    during a connection handshake. A remote attacker could
    use this flaw to make a TLS/SSL server consume an
    excessive amount of CPU and fail to accept connections
    form other clients. (CVE-2016-8610)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1702&L=scientific-linux-errata&F=&S=&P=3925
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f8b0853"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-48.el6_8.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-48.el6_8.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-48.el6_8.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-48.el6_8.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-48.el6_8.4")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-1.0.1e-60.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1e-60.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-60.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-60.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-60.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-60.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
