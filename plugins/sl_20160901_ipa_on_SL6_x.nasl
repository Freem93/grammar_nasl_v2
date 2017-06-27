#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(93340);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/19 14:25:14 $");

  script_cve_id("CVE-2016-5404");

  script_name(english:"Scientific Linux Security Update : ipa on SL6.x, SL7.x i386/x86_64");
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

  - An insufficient permission check issue was found in the
    way IPA server treats certificate revocation requests.
    An attacker logged in with the 'retrieve certificate'
    permission enabled could use this flaw to revoke
    certificates, possibly triggering a denial of service
    attack. (CVE-2016-5404)

This issue was discovered by Fraser Tweedale (Red Hat).

For SL7.0 and SL7.1 only, this includes updated packages for sssd,
mod_auth_gssapi, and slapi-nis to satisfy dependencies."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1609&L=scientific-linux-errata&F=&S=&P=80
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b818708"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"ipa-admintools-3.0.0-50.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-client-3.0.0-50.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-debuginfo-3.0.0-50.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-python-3.0.0-50.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-3.0.0-50.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-selinux-3.0.0-50.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-trust-ad-3.0.0-50.el6_8.2")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-admintools-4.2.0-15.sl7_2.19")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.2.0-15.sl7_2.19")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.2.0-15.sl7_2.19")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-python-4.2.0-15.sl7_2.19")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.2.0-15.sl7_2.19")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-dns-4.2.0-15.sl7_2.19")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.2.0-15.sl7_2.19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
