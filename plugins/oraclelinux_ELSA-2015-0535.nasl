#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0535 and 
# Oracle Linux Security Advisory ELSA-2015-0535 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81807);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2014-7300");
  script_bugtraq_id(70178);
  script_xref(name:"RHSA", value:"2015:0535");

  script_name(english:"Oracle Linux 7 : GNOME / Shell (ELSA-2015-0535)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0535 :

Updated gnome-shell, mutter, clutter, and cogl packages that fix one
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
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004881.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome and / or shell packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cogl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cogl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cogl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"clutter-1.14.4-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"clutter-devel-1.14.4-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"clutter-doc-1.14.4-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cogl-1.14.0-6.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cogl-devel-1.14.0-6.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"cogl-doc-1.14.0-6.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnome-shell-3.8.4-45.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnome-shell-browser-plugin-3.8.4-45.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mutter-3.8.4-16.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mutter-devel-3.8.4-16.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clutter / clutter-devel / clutter-doc / cogl / cogl-devel / etc");
}
