#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1540 and 
# Oracle Linux Security Advisory ELSA-2013-1540 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71126);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 17:16:05 $");

  script_cve_id("CVE-2013-4166");
  script_osvdb_id(95631);
  script_xref(name:"RHSA", value:"2013:1540");

  script_name(english:"Oracle Linux 6 : evolution (ELSA-2013-1540)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1540 :

Updated evolution packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Evolution is the integrated collection of email, calendaring, contact
management, communications, and personal information management (PIM)
tools for the GNOME desktop environment.

A flaw was found in the way Evolution selected GnuPG public keys when
encrypting emails. This could result in emails being encrypted with
public keys other than the one belonging to the intended recipient.
(CVE-2013-4166)

The Evolution packages have been upgraded to upstream version 2.32.3,
which provides a number of bug fixes and enhancements over the
previous version. These changes include implementation of Gnome XDG
Config Folders, and support for Exchange Web Services (EWS) protocol
to connect to Microsoft Exchange servers. EWS support has been added
as a part of the evolution-exchange packages. (BZ#883010, BZ#883014,
BZ#883015, BZ#883017, BZ#524917, BZ#524921, BZ#883044)

The gtkhtml3 packages have been upgraded to upstream version 2.32.2,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#883019)

The libgdata packages have been upgraded to upstream version 0.6.4,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#883032)

This update also fixes the following bug :

* The Exchange Calendar could not fetch the 'Free' and 'Busy'
information for meeting attendees when using Microsoft Exchange 2010
servers, and this information thus could not be displayed. This
happened because Microsoft Exchange 2010 servers use more strict rules
for 'Free' and 'Busy' information fetching. With this update, the
respective code in the openchange packages has been modified so the
'Free' and 'Busy' information fetching now complies with the fetching
rules on Microsoft Exchange 2010 servers. The 'Free' and 'Busy'
information can now be displayed as expected in the Exchange Calendar.
(BZ#665967)

All Evolution users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements. All running instances of Evolution must be restarted for
this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-November/003824.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cheese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:control-center-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:control-center-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ekiga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-exchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-mapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-panel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-panel-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-brasero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-bugbuddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-gnomedesktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-gnomekeyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-gnomeprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-gtksourceview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-libgtop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-libwnck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-metacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkhtml3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkhtml3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgdata-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-sendto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-sendto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openchange-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openchange-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openchange-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:planner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:planner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:planner-eds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-jamendo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-mozplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-upnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-youtube");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/29");
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
if (rpm_check(release:"EL6", reference:"cheese-2.28.1-8.el6")) flag++;
if (rpm_check(release:"EL6", reference:"control-center-2.28.1-39.el6")) flag++;
if (rpm_check(release:"EL6", reference:"control-center-devel-2.28.1-39.el6")) flag++;
if (rpm_check(release:"EL6", reference:"control-center-extra-2.28.1-39.el6")) flag++;
if (rpm_check(release:"EL6", reference:"control-center-filesystem-2.28.1-39.el6")) flag++;
if (rpm_check(release:"EL6", reference:"ekiga-3.2.6-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-2.32.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-data-server-2.32.3-18.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-data-server-devel-2.32.3-18.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-data-server-doc-2.32.3-18.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-devel-2.32.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-devel-docs-2.32.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-exchange-2.32.3-16.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-help-2.32.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-mapi-0.32.2-12.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-mapi-devel-0.32.2-12.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-perl-2.32.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-pst-2.32.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"evolution-spamassassin-2.32.3-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"finch-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"finch-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-panel-2.30.2-15.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-panel-devel-2.30.2-15.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-panel-libs-2.30.2-15.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-applet-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-brasero-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-bugbuddy-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-desktop-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-evince-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-evolution-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-gnomedesktop-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-gnomekeyring-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-gnomeprint-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-gtksourceview-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-libgtop2-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-libwnck-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-metacity-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-rsvg-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnome-python2-totem-2.28.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gtkhtml3-3.32.2-2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gtkhtml3-devel-3.32.2-2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libgdata-0.6.4-2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libgdata-devel-0.6.4-2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-perl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libpurple-tcl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nautilus-sendto-2.28.2-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"nautilus-sendto-devel-2.28.2-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openchange-1.0-6.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openchange-client-1.0-6.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openchange-devel-1.0-6.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openchange-devel-docs-1.0-6.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-docs-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pidgin-perl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"EL6", reference:"planner-0.14.4-10.el6")) flag++;
if (rpm_check(release:"EL6", reference:"planner-devel-0.14.4-10.el6")) flag++;
if (rpm_check(release:"EL6", reference:"planner-eds-0.14.4-10.el6")) flag++;
if (rpm_check(release:"EL6", reference:"totem-2.28.6-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"totem-devel-2.28.6-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"totem-jamendo-2.28.6-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"totem-mozplugin-2.28.6-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"totem-nautilus-2.28.6-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"totem-upnp-2.28.6-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"totem-youtube-2.28.6-4.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cheese / control-center / control-center-devel / etc");
}
