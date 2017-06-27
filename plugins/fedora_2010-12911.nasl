#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-12911.
#

include("compat.inc");

if (description)
{
  script_id(48391);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-1172");
  script_bugtraq_id(42347);
  script_osvdb_id(67026);
  script_xref(name:"FEDORA", value:"2010-12911");

  script_name(english:"Fedora 12 : DeviceKit-power-014-2.fc12 / ModemManager-0.4-5.git20100720.fc12 / etc (2010-12911)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that dbus-glib did not enforce the 'access' flag on
exported GObject properties. If such a property were read/write
internally but specified as read-only externally, a malicious, local
user could use this flaw to modify that property of an application.
Such a change could impact the application's behavior (for example, if
an IP address were changed the network may not come up properly after
reboot) and possibly lead to a denial of service. (CVE-2010-1172) Due
to the way dbus-glib translates an application's XML definitions of
service interfaces and properties into C code at application build
time, applications built against dbus-glib that use read-only
properties needed to be rebuilt to fully fix the flaw. This update
provides NetworkManager, ModemManager and DeviceKit-power packages
that have been rebuilt against the updated dbus-glib packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=585394"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ccebde1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60d3aac4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f8c5256"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8421f4f4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:DeviceKit-power");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ModemManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"DeviceKit-power-014-2.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"ModemManager-0.4-5.git20100720.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"NetworkManager-0.8.1-3.git20100813.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"dbus-glib-0.86-3.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "DeviceKit-power / ModemManager / NetworkManager / dbus-glib");
}
