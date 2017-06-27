#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(96280);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/04 15:13:58 $");

  script_cve_id("CVE-2016-7030", "CVE-2016-9575");

  script_name(english:"Scientific Linux Security Update : ipa on SL7.x x86_64");
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

  - It was discovered that the default IdM password policies
    that lock out accounts after a certain number of failed
    login attempts were also applied to host and service
    accounts. A remote unauthenticated user could use this
    flaw to cause a denial of service attack against
    kerberized services. (CVE-2016-7030)

  - It was found that IdM's certprofile-mod command did not
    properly check the user's permissions while modifying
    certificate profiles. An authenticated, unprivileged
    attacker could use this flaw to modify profiles to issue
    certificates with arbitrary naming or key usage
    information and subsequently use such certificates for
    other attacks. (CVE-2016-9575)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=78
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?506d2d57"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/04");
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
if (rpm_check(release:"SL7", reference:"ipa-admintools-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-client-common-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-common-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-python-compat-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-common-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-dns-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaclient-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipalib-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaserver-4.4.0-14.sl7_3.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
