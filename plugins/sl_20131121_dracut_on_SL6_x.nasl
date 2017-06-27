#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71297);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/10 14:13:50 $");

  script_cve_id("CVE-2012-4453");

  script_name(english:"Scientific Linux Security Update : dracut on SL6.x (noarch)");
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
"It was discovered that dracut created initramfs images as world
readable. A local user could possibly use this flaw to obtain
sensitive information from these files, such as iSCSI authentication
passwords, encrypted root file system crypttab passwords, or other
information. (CVE-2012-4453)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=3190
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccea865b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (rpm_check(release:"SL6", reference:"dracut-004-336.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-caps-004-336.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-fips-004-336.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-fips-aesni-004-336.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-generic-004-336.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-kernel-004-336.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-network-004-336.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-tools-004-336.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
