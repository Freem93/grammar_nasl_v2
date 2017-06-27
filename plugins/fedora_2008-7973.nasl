#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-7973.
#

include("compat.inc");

if (description)
{
  script_id(34183);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 22:23:17 $");

  script_xref(name:"FEDORA", value:"2008-7973");

  script_name(english:"Fedora 8 : libHX-1.23-1.fc8 / pam_mount-0.47-1.fc8 (2008-7973)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security flaw in the pam_mount's handling of user defined volumes
using the 'luserconf' option has been fixed in this update. The
vulnerability allowed users to arbitrarily mount filesystems at
arbitrary locations. More details about this vulnerability can be
found in the announcement message sent to the pam-mount-user
mailinglist at SourceForge: http://sourceforge.net/mailarchive/me
ssage.php?msg_name=alpine.LNX.1.10.0809042353120.17569%40fbirervta.pbz
chgretzou. qr The pam_mount facility now uses a configuration file
written in XML. The /etc/security/pam_mount.conf file will be
converted to /etc/security/pam_mount.conf.xml during update with
/usr/bin/convert_pam_mount_conf.pl, which removes all comments. Any
per-user configuration files must be converted manually, with the
conversion script if desired. A sample pam_mount.conf.xml file with
detailed comments about the available options appears at
/usr/share/doc/pam_mount-*/pam_mount.conf.xml. Note: This update also
introduces a new version of libHX, which is required by updated
pam_mount.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/mailarchive/me"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=461464"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014252.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7698453c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96d4da5e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libHX and / or pam_mount packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libHX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pam_mount");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/12");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"libHX-1.23-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pam_mount-0.47-1.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libHX / pam_mount");
}
