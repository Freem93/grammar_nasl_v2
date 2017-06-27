#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85564);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2015-3238");

  script_name(english:"Scientific Linux Security Update : pam on SL6.x, SL7.x i386/x86_64");
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
"It was discovered that the _unix_run_helper_binary() function of PAM's
unix_pam module could write to a blocking pipe, possibly causing the
function to become unresponsive. An attacker able to supply large
passwords to the unix_pam module could use this flaw to enumerate
valid user accounts, or cause a denial of service on the system.
(CVE-2015-3238)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=21406
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?329042cd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pam, pam-debuginfo and / or pam-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"pam-1.1.1-20.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"pam-debuginfo-1.1.1-20.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"pam-devel-1.1.1-20.el6_7.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pam-1.1.8-12.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pam-debuginfo-1.1.8-12.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pam-devel-1.1.8-12.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
