#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0516 and 
# Oracle Linux Security Advisory ELSA-2013-0516 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68753);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2011-3201");
  script_bugtraq_id(58086);
  script_osvdb_id(91170);
  script_xref(name:"RHSA", value:"2013:0516");

  script_name(english:"Oracle Linux 6 : evolution (ELSA-2013-0516)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0516 :

Updated evolution packages that fix one security issue and three bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Evolution is the GNOME mailer, calendar, contact manager and
communication tool. The components which make up Evolution are tightly
integrated with one another and act as a seamless personal
information-management tool.

The way Evolution handled mailto URLs allowed any file to be attached
to the new message. This could lead to information disclosure if the
user did not notice the attached file before sending the message. With
this update, mailto URLs cannot be used to attach certain files, such
as hidden files or files in hidden directories, files in the /etc/
directory, or files specified using a path containing '..'.
(CVE-2011-3201)

Red Hat would like to thank Matt McCutchen for reporting this issue.

This update also fixes the following bugs :

* Creating a contact list with contact names encoded in UTF-8 caused
these names to be displayed in the contact list editor in the ASCII
encoding instead of UTF-8. This bug has been fixed and the contact
list editor now displays the names in the correct format. (BZ#707526)

* Due to a bug in the evolution-alarm-notify process, calendar
appointment alarms did not appear in some types of calendars. The
underlying source code has been modified and calendar notifications
work as expected. (BZ#805239)

* An attempt to print a calendar month view as a PDF file caused
Evolution to terminate unexpectedly. This update applies a patch to
fix this bug and Evolution no longer crashes in this situation.
(BZ#890642)

All evolution users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
instances of Evolution must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003275.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-conduits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"evolution-2.28.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-conduits-2.28.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-devel-2.28.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-help-2.28.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-perl-2.28.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-pst-2.28.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-spamassassin-2.28.3-30.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution / evolution-conduits / evolution-devel / evolution-help / etc");
}
