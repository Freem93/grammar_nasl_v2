#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61365);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-0441");

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
"Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way the ASN.1 (Abstract Syntax Notation One)
decoder in NSS handled zero length items. This flaw could cause the
decoder to incorrectly skip or replace certain items with a default
value, or could cause an application to crash if, for example, it
received a specially crafted OCSP (Online Certificate Status Protocol)
response. (CVE-2012-0441)

The nspr package has been upgraded to upstream version 4.9.1, which
provides a number of bug fixes and enhancements over the previous
version.

The nss-util package has been upgraded to upstream version 3.13.5,
which provides a number of bug fixes and enhancements over the
previous version.

The nss package has been upgraded to upstream version 3.13.5, which
provides a number of bug fixes and enhancements over the previous
version.

All NSS, NSPR, and nss-util users are advised to upgrade to these
updated packages, which correct these issues and add these
enhancements. After installing this update, applications using NSS,
NSPR, or nss-util must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=5183
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f242659e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
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
if (rpm_check(release:"SL6", reference:"nspr-4.9.1-2.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-debuginfo-4.9.1-2.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-devel-4.9.1-2.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.13.5-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
