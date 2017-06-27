#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-7767.
#

include("compat.inc");

if (description)
{
  script_id(83338);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 23:14:53 $");

  script_cve_id("CVE-2015-2924");
  script_xref(name:"FEDORA", value:"2015-7767");

  script_name(english:"Fedora 22 : NetworkManager-1.0.2-1.fc22 / NetworkManager-openconnect-1.0.2-1.fc22 / etc (2015-7767)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update of NetworkManager, the VPN plugins, applet and
connection editor to 1.0.2 stable release.

The update includes bug fixes, feature additions, translation updates
and a fix for the CVE-2015-2924 denial of service security issue with
low impact.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1209902"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157798.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21475616"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157799.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d79896f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bef831cf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157801.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?963d91ca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2faa90e2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157803.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75df4d83"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-openconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-vpnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"NetworkManager-1.0.2-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"NetworkManager-openconnect-1.0.2-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"NetworkManager-openswan-1.0.2-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"NetworkManager-openvpn-1.0.2-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"NetworkManager-vpnc-1.0.2-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"network-manager-applet-1.0.2-1.fc22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-openconnect / etc");
}
