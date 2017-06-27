#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0516. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64764);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2011-3201");
  script_osvdb_id(91170);
  script_xref(name:"RHSA", value:"2013:0516");

  script_name(english:"RHEL 6 : evolution (RHSA-2013:0516)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3201.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0516.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-conduits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0516";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evolution-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evolution-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evolution-conduits-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evolution-conduits-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evolution-debuginfo-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evolution-debuginfo-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evolution-devel-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evolution-devel-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"evolution-help-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evolution-perl-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evolution-perl-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evolution-pst-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evolution-pst-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"evolution-spamassassin-2.28.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"evolution-spamassassin-2.28.3-30.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution / evolution-conduits / evolution-debuginfo / etc");
  }
}
