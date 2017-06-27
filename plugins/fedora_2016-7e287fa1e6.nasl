#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-7e287fa1e6.
#

include("compat.inc");

if (description)
{
  script_id(90961);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/09 15:53:04 $");

  script_xref(name:"FEDORA", value:"2016-7e287fa1e6");

  script_name(english:"Fedora 24 : NetworkManager-1.2.0-1.fc24 / NetworkManager-fortisslvpn-1.2.0-1.fc24 / etc (2016-7e287fa1e6)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 1.2.0 release. * Announcement:
https://mail.gnome.org/archives
/networkmanager-list/2016-April/msg00064.html * A blog post:
https://blogs.gnome.org/lkundrak/2016/04/20/networkmanager-1-2-is-here
/

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://blogs.gnome.org/lkundrak/2016/04/20/networkmanager-1-2-is-here/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f8e61a5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1129818"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?debaeda5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184113.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd6d2c8f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184114.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec93e443"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfbaa413"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?597ad3e5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bd17797"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5570d368"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd38877f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5b50c36"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd22dde3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/184122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21e1548c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mail.gnome.org/archives"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-fortisslvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-iodine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-l2tp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-openconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-pptp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-vpnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC24", reference:"NetworkManager-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-fortisslvpn-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-iodine-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-l2tp-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-libreswan-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-openconnect-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-openvpn-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-pptp-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-ssh-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"NetworkManager-vpnc-1.2.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"network-manager-applet-1.2.0-1.fc24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-fortisslvpn / NetworkManager-iodine / etc");
}
