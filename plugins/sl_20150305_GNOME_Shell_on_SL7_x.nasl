#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82249);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/26 13:38:48 $");

  script_cve_id("CVE-2014-7300");

  script_name(english:"Scientific Linux Security Update : GNOME Shell on SL7.x x86_64");
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
"It was found that the GNOME shell did not disable the Print Screen key
when the screen was locked. This could allow an attacker with physical
access to a system with a locked screen to crash the screen-locking
application by creating a large amount of screenshots. (CVE-2014-7300)

This update also fixes the following bugs :

  - The Timed Login feature, which automatically logs in a
    specified user after a specified period of time, stopped
    working after the first user of the GUI logged out. This
    has been fixed, and the specified user is always logged
    in if no one else logs in.

  - If two monitors were arranged vertically with the
    secondary monitor above the primary monitor, it was
    impossible to move windows onto the secondary monitor.
    With this update, windows can be moved through the upper
    edge of the first monitor to the secondary monitor.

  - If the Gnome Display Manager (GDM) user list was
    disabled and a user entered the user name, the password
    prompt did not appear. Instead, the user had to enter
    the user name one more time. The GDM code that contained
    this error has been fixed, and users can enter their
    user names and passwords as expected.

  - Prior to this update, only a small area was available on
    the GDM login screen for a custom text banner. As a
    consequence, when a long banner was used, it did not fit
    into the area, and the person reading the banner had to
    use scrollbars to view the whole text. With this update,
    more space is used for the banner if necessary, which
    allows the user to read the message conveniently.

  - When the Cancel button was pressed while an LDAP user
    name and password was being validated, the GDM code did
    not handle the situation correctly. As a consequence,
    GDM became unresponsive, and it was impossible to return
    to the login screen. The affected code has been fixed,
    and LDAP user validation can be canceled, allowing
    another user to log in instead.

  - If the window focus mode in GNOME was set to 'mouse' or
    'sloppy', navigating through areas of a pop-up menu
    displayed outside its parent window caused the window to
    lose its focus. Consequently, the menu was not usable.
    This has been fixed, and the window focus is kept in
    under this scenario.

  - If user authentication is configured to require a smart
    card to log in, user names are obtained from the smart
    card. The authentication is then performed by entering
    the smart card PIN. Prior to this update, the login
    screen allowed a user name to be entered if no smart
    card was inserted, but due to a bug in the underlying
    code, the screen became unresponsive. If, on the other
    hand, a smart card was used for authentication, the user
    was logged in as soon as the authentication was
    complete. As a consequence, it was impossible to select
    a session other than GNOME Classic. Both of these
    problems have been fixed. Now, a smart card is required
    when this type of authentication is enabled, and any
    other installed session can be selected by the user.

In addition, this update adds the following enhancement :

  - Support for quad-buffer OpenGL stereo visuals has been
    added. As a result, OpenGL applications that use
    quad-buffer stereo can be run and properly displayed
    within the GNOME desktop when used with a video driver
    and hardware with the necessary capabilities."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=3492
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a75cc1ce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"clutter-1.14.4-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"clutter-debuginfo-1.14.4-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"clutter-devel-1.14.4-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"clutter-doc-1.14.4-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cogl-1.14.0-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cogl-debuginfo-1.14.0-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cogl-devel-1.14.0-6.el7")) flag++;
if (rpm_check(release:"SL7", reference:"cogl-doc-1.14.0-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-3.8.4-45.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-browser-plugin-3.8.4-45.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-debuginfo-3.8.4-45.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mutter-3.8.4-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mutter-debuginfo-3.8.4-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mutter-devel-3.8.4-16.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
