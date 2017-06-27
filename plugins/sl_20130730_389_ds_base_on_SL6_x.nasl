#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(69163);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/08/02 10:42:45 $");

  script_cve_id("CVE-2013-2219");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL6.x i386/x86_64");
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
"It was discovered that the 389 Directory Server did not honor defined
attribute access controls when evaluating search filter expressions. A
remote attacker (with permission to query the Directory Server) could
use this flaw to determine the values of restricted attributes via a
series of search queries with filter conditions that used restricted
attributes. (CVE-2013-2219)

This update also fixes the following bugs :

  - Previously, the disk monitoring feature did not function
    properly. If logging functionality was set to critical
    and logging was disabled, rotated logs would be deleted.
    If the attribute 'nsslapd-errorlog-level' was explicitly
    set to any value, even zero, the disk monitoring feature
    would not stop the Directory Server when it was supposed
    to. This update corrects the disk monitoring feature
    settings, and it no longer malfunctions in the described
    scenarios.

  - Previously, setting the
    'nsslapd-disk-monitoring-threshold' attribute via
    ldapmodify to a large value worked as expected; however,
    a bug in ldapsearch caused such values for the option to
    be displayed as negative values. This update corrects
    the bug in ldapsearch and correct values are now
    displayed.

  - If logging functionality was not set to critical, then
    the mount point for the logs directory was incorrectly
    skipped during the disk space check.

After installing this update, the 389 server service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1307&L=scientific-linux-errata&T=0&P=2568
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e7dab3e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/31");
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
if (rpm_check(release:"SL6", reference:"389-ds-base-1.2.11.15-20.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-debuginfo-1.2.11.15-20.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-devel-1.2.11.15-20.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-libs-1.2.11.15-20.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
