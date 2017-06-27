#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99217);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2016-8610", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337");

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
"The following packages have been upgraded to a later upstream version:
gnutls (2.12.23).

Security Fix(es) :

  - A denial of service flaw was found in the way the
    TLS/SSL protocol defined processing of ALERT packets
    during a connection handshake. A remote attacker could
    use this flaw to make a TLS/SSL server consume an
    excessive amount of CPU and fail to accept connections
    form other clients. (CVE-2016-8610)

  - Multiple flaws were found in the way gnutls processed
    OpenPGP certificates. An attacker could create specially
    crafted OpenPGP certificates which, when parsed by
    gnutls, would cause it to crash. (CVE-2017-5335,
    CVE-2017-5336, CVE-2017-5337)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=396
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b86cc99"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
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
if (rpm_check(release:"SL6", reference:"gnutls-2.12.23-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-debuginfo-2.12.23-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-devel-2.12.23-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-guile-2.12.23-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-utils-2.12.23-21.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
