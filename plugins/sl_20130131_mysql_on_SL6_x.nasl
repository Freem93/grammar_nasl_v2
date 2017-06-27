#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64426);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2012-0572", "CVE-2012-0574", "CVE-2012-1702", "CVE-2012-1705", "CVE-2013-0375", "CVE-2013-0383", "CVE-2013-0384", "CVE-2013-0385", "CVE-2013-0389");

  script_name(english:"Scientific Linux Security Update : mysql on SL6.x i386/x86_64");
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
"After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=211
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3741ae2d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"mysql-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-bench-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-debuginfo-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-devel-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-embedded-devel-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-libs-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-server-5.1.67-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"mysql-test-5.1.67-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
