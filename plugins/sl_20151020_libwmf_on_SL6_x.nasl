#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(86489);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/10/21 22:57:46 $");

  script_cve_id("CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");

  script_name(english:"Scientific Linux Security Update : libwmf on SL6.x, SL7.x i386/x86_64");
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
"It was discovered that libwmf did not correctly process certain WMF
(Windows Metafiles) with embedded BMP images. By tricking a victim
into opening a specially crafted WMF file in an application using
libwmf, a remote attacker could possibly use this flaw to execute
arbitrary code with the privileges of the user running the
application. (CVE-2015-0848, CVE-2015-4588)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash or execute arbitrary code with the
privileges of the user running the application. (CVE-2015-4696)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash. (CVE-2015-4695)

After installing the update, all applications using libwmf must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1510&L=scientific-linux-errata&F=&S=&P=2224
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05197a0f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libwmf-0.2.8.4-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libwmf-debuginfo-0.2.8.4-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libwmf-devel-0.2.8.4-25.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libwmf-lite-0.2.8.4-25.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwmf-0.2.8.4-41.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwmf-debuginfo-0.2.8.4-41.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwmf-devel-0.2.8.4-41.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwmf-lite-0.2.8.4-41.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
