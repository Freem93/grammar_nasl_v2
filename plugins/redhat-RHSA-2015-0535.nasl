#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0535. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81639);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-7300");
  script_xref(name:"RHSA", value:"2015:0535");

  script_name(english:"RHEL 7 : GNOME Shell (RHSA-2015:0535)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnome-shell, mutter, clutter, and cogl packages that fix one
security issue, several bugs, and add one enhancement are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

GNOME Shell and the packages it depends upon provide the core user
interface of the Red Hat Enterprise Linux desktop, including functions
such as navigating between windows and launching applications.

It was found that the GNOME shell did not disable the Print Screen key
when the screen was locked. This could allow an attacker with physical
access to a system with a locked screen to crash the screen-locking
application by creating a large amount of screenshots. (CVE-2014-7300)

This update also fixes the following bugs :

* The Timed Login feature, which automatically logs in a specified
user after a specified period of time, stopped working after the first
user of the GUI logged out. This has been fixed, and the specified
user is always logged in if no one else logs in. (BZ#1043571)

* If two monitors were arranged vertically with the secondary monitor
above the primary monitor, it was impossible to move windows onto the
secondary monitor. With this update, windows can be moved through the
upper edge of the first monitor to the secondary monitor. (BZ#1075240)

* If the Gnome Display Manager (GDM) user list was disabled and a user
entered the user name, the password prompt did not appear. Instead,
the user had to enter the user name one more time. The GDM code that
contained this error has been fixed, and users can enter their user
names and passwords as expected. (BZ#1109530)

* Prior to this update, only a small area was available on the GDM
login screen for a custom text banner. As a consequence, when a long
banner was used, it did not fit into the area, and the person reading
the banner had to use scrollbars to view the whole text. With this
update, more space is used for the banner if necessary, which allows
the user to read the message conveniently. (BZ#1110036)

* When the Cancel button was pressed while an LDAP user name and
password was being validated, the GDM code did not handle the
situation correctly. As a consequence, GDM became unresponsive, and it
was impossible to return to the login screen. The affected code has
been fixed, and LDAP user validation can be canceled, allowing another
user to log in instead. (BZ#1137041)

* If the window focus mode in GNOME was set to 'mouse' or 'sloppy',
navigating through areas of a pop-up menu displayed outside its parent
window caused the window to lose its focus. Consequently, the menu was
not usable. This has been fixed, and the window focus is kept in under
this scenario. (BZ#1149585)

* If user authentication is configured to require a smart card to log
in, user names are obtained from the smart card. The authentication is
then performed by entering the smart card PIN. Prior to this update,
the login screen allowed a user name to be entered if no smart card
was inserted, but due to a bug in the underlying code, the screen
became unresponsive. If, on the other hand, a smart card was used for
authentication, the user was logged in as soon as the authentication
was complete. As a consequence, it was impossible to select a session
other than GNOME Classic. Both of these problems have been fixed. Now,
a smart card is required when this type of authentication is enabled,
and any other installed session can be selected by the user.
(BZ#1159385, BZ#1163474)

In addition, this update adds the following enhancement :

* Support for quad-buffer OpenGL stereo visuals has been added. As a
result, OpenGL applications that use quad-buffer stereo can be run and
properly displayed within the GNOME desktop when used with a video
driver and hardware with the necessary capabilities. (BZ#861507,
BZ#1108890, BZ#1108891, BZ# 1108893)

All GNOME Shell users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7300.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0535.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cogl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cogl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cogl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cogl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0535";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL7", reference:"clutter-1.14.4-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"clutter-debuginfo-1.14.4-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"clutter-devel-1.14.4-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"clutter-doc-1.14.4-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"clutter-doc-1.14.4-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"cogl-1.14.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"cogl-debuginfo-1.14.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"cogl-devel-1.14.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"cogl-doc-1.14.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gnome-shell-3.8.4-45.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gnome-shell-3.8.4-45.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gnome-shell-browser-plugin-3.8.4-45.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gnome-shell-browser-plugin-3.8.4-45.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gnome-shell-debuginfo-3.8.4-45.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gnome-shell-debuginfo-3.8.4-45.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mutter-3.8.4-16.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mutter-debuginfo-3.8.4-16.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mutter-devel-3.8.4-16.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clutter / clutter-debuginfo / clutter-devel / clutter-doc / cogl / etc");
  }
}
