#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82987);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/30 13:50:20 $");

  script_cve_id("CVE-2013-7423", "CVE-2015-1781");

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
"A buffer overflow flaw was found in the way glibc's gethostbyname_r()
and other related functions computed the size of a buffer when passed
a misaligned buffer as input. An attacker able to make an application
call any of these functions with a misaligned buffer could use this
flaw to crash the application or, potentially, execute arbitrary code
with the permissions of the user running the application.
(CVE-2015-1781)

It was discovered that, under certain circumstances, glibc's
getaddrinfo() function would send DNS queries to random file
descriptors. An attacker could potentially use this flaw to send DNS
queries to unintended recipients, resulting in information disclosure
or data loss due to the application encountering corrupted data.
(CVE-2013-7423)

This update also fixes the following bug :

  - Previously, the nscd daemon did not properly reload
    modified data when the user edited monitored nscd
    configuration files. As a consequence, nscd returned
    stale data to system processes. This update adds a
    system of inotify-based monitoring and stat-based backup
    monitoring for nscd configuration files. As a result,
    nscd now detects changes to its configuration files and
    reloads the data properly, which prevents it from
    returning stale data."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1504&L=scientific-linux-errata&T=0&P=2169
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51a607cf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.149.el6_6.7")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.149.el6_6.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
