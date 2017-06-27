#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61194);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-1072");

  script_name(english:"Scientific Linux Security Update : php-pear on SL6.x");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The php-pear package contains the PHP Extension and Application
Repository (PEAR), a framework and distribution system for reusable
PHP components.

It was found that the 'pear' command created temporary files in an
insecure way when installing packages. A malicious, local user could
use this flaw to conduct a symbolic link attack, allowing them to
overwrite the contents of arbitrary files accessible to the victim
running the 'pear install' command. (CVE-2011-1072)

This update also fixes the following bugs :

  - The php-pear package has been upgraded to version 1.9.4,
    which provides a number of bug fixes over the previous
    version.

  - Prior to this update, php-pear created a cache in the
    '/var/cache/php-pear/' directory when attempting to list
    all packages. As a consequence, php-pear failed to
    create or update the cache file as a regular user
    without sufficient file permissions and could not list
    all packages. With this update, php-pear no longer fails
    if writing to the cache directory is not permitted. Now,
    all packages are listed as expected.

All users of php-pear are advised to upgrade to this updated package,
which corrects these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=2275
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d132378"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"php-pear-1.9.4-4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
