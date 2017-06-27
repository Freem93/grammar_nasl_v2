#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0516 and 
# CentOS Errata and Security Advisory 2013:0516 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65148);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2011-3201");
  script_bugtraq_id(58086);
  script_osvdb_id(91170);
  script_xref(name:"RHSA", value:"2013:0516");

  script_name(english:"CentOS 6 : evolution (CESA-2013:0516)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix one security issue and three bugs
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
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019304.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?323d6986"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000506.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d291e22a"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-conduits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"evolution-2.28.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-conduits-2.28.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-devel-2.28.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-help-2.28.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-perl-2.28.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-pst-2.28.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-spamassassin-2.28.3-30.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
