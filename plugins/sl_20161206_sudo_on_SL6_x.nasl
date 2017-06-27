#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95871);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/26 13:35:46 $");

  script_cve_id("CVE-2016-7032", "CVE-2016-7076");

  script_name(english:"Scientific Linux Security Update : sudo on SL6.x, SL7.x i386/x86_64");
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

  - It was discovered that the sudo noexec restriction could
    have been bypassed if application run via sudo executed
    system(), popen(), or wordexp() C library functions with
    a user-supplied argument. A local user permitted to run
    such application via sudo with noexec restriction could
    use these flaws to execute arbitrary commands with
    elevated privileges. (CVE-2016-7032, CVE-2016-7076)

These issues were discovered by Florian Weimer (Red Hat)."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=16295
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ccd071e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo, sudo-debuginfo and / or sudo-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"sudo-1.8.6p3-25.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"sudo-debuginfo-1.8.6p3-25.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"sudo-devel-1.8.6p3-25.el6_8")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sudo-1.8.6p7-21.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sudo-debuginfo-1.8.6p7-21.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sudo-devel-1.8.6p7-21.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
