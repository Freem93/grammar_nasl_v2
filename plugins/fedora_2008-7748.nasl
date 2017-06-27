#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-7748.
#

include("compat.inc");

if (description)
{
  script_id(34150);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:23:17 $");

  script_xref(name:"FEDORA", value:"2008-7748");

  script_name(english:"Fedora 9 : PackageKit-0.2.5-1.fc9 / fedora-release-9-5.transition / gnome-packagekit-0.2.5-2.fc9 (2008-7748)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This fedora-release update introduces a new set of Fedora Updates and
Updates Testing repo definitions. These new definitions point to new
URLS for our update content signed with a new key. This update also
provides Fedora 8 and 9's new package signing keys. This update is a
transitional update to direct users at the rest of the updates in the
new locations. It will be superseded by further fedora-release updates
at a future date. The Fedora 9 update also includes new versions of
PackageKit and gnome-packagekit to better handle importing of our new
key. If you are using PackageKit it is recommended that you reboot
after installing this update so that PackageKit can get a fresh look
at the new repodata from the new repo definitions. See
https://fedoraproject.org/wiki/Enabling_new_signing_key for more
details. This update adds the ia64 secondary arch key as well as
arranges GPG keys by arch and refers to them by arch in yum repo
configs. This allows the secondary arch key to only be used on
secondary arches and allows the fedora-release package to continue to
be noarch. Also this update changes the commented out baseurl from
download.fedora.redhat.com to download.fedoraproject.org.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Enabling_new_signing_key"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/013667.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94b1d07a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/013668.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a455afe5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/013669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5da8806"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b0418ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d4742d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0ba6c3b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected PackageKit, fedora-release and / or
gnome-packagekit packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fedora-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-packagekit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"PackageKit-0.2.5-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"fedora-release-9-5.transition")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-packagekit-0.2.5-2.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / fedora-release / gnome-packagekit");
}
