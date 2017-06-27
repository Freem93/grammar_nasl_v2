#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78844);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/04 14:19:38 $");

  script_cve_id("CVE-2013-4237", "CVE-2013-4458");

  script_name(english:"Scientific Linux Security Update : glibc on SL6.x i386/x86_64");
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
"An out-of-bounds write flaw was found in the way the glibc's
readdir_r() function handled file system entries longer than the
NAME_MAX character constant. A remote attacker could provide a
specially crafted NTFS or CIFS file system that, when processed by an
application using readdir_r(), would cause that application to crash
or, potentially, allow the attacker to execute arbitrary code with the
privileges of the user running the application. (CVE-2013-4237)

It was found that getaddrinfo() did not limit the amount of stack
memory used during name resolution. An attacker able to make an
application resolve an attacker-controlled hostname or IP address
could possibly cause the application to exhaust all stack memory and
crash. (CVE-2013-4458)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=1353
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?280ec385"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.149.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.149.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
