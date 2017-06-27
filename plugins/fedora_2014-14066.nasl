#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-14066.
#

include("compat.inc");

if (description)
{
  script_id(79391);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:14:42 $");

  script_cve_id("CVE-2013-6403");
  script_bugtraq_id(63926);
  script_xref(name:"FEDORA", value:"2014-14066");

  script_name(english:"Fedora 19 : owncloud-5.0.17-2.fc19 / php-sabredav-Sabre_CalDAV-1.7.9-1.fc19 / etc (2014-14066)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides ownCloud 5.0.17, the latest release in the 5.x
series, plus an extra security-related fix backported from the stable5
branch.

It also provides SabreDAV 1.7.13. This is also a major upgrade from
SabreDAV 1.6, and has API incompatibilities. ownCloud is the only
Fedora 19 package that requires SabreDAV, and ownCloud 5 cannot work
with SabreDAV 1.6: the API-incompatible upgrade is unfortunate but
necessary to provide a secure ownCloud release.

ownCloud 4.5, the current version in Fedora 19, is un-maintained,
subject to known security issues, and has no upgrade path beyond
ownCloud 5. Upgrading directly from 4.5 to the current version in
Fedora 20 or 21 - ownCloud 7 - would likely fail.

I plan to update the package to 6.x before Fedora 19 goes EOL and
maintain the 5.x and 6.x builds in a side repository to make sure
there is a viable upgrade path from Fedora 19.

Initial testing on the 4.x -> 5.x upgrade has been performed, but
please back up your user data, ownCloud configuration and ownCloud
database before performing the upgrade. Please file negative karma and
a bug report for any issues encountered during the upgrade. Ideally,
the upgrade should run smoothly on first access to the updated
ownCloud instance with no manual intervention required.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1035593"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f1a8163"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e0e4b73"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87ba4cd8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f34faccd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?438d8ca8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d33d8d07"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60dd41d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:owncloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-sabredav-Sabre_CalDAV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-sabredav-Sabre_CardDAV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-sabredav-Sabre_DAV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-sabredav-Sabre_DAVACL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-sabredav-Sabre_HTTP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-sabredav-Sabre_VObject");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"owncloud-5.0.17-2.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"php-sabredav-Sabre_CalDAV-1.7.9-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"php-sabredav-Sabre_CardDAV-1.7.9-2.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"php-sabredav-Sabre_DAV-1.7.13-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"php-sabredav-Sabre_DAVACL-1.7.9-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"php-sabredav-Sabre_HTTP-1.7.11-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"php-sabredav-Sabre_VObject-2.1.4-1.fc19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "owncloud / php-sabredav-Sabre_CalDAV / php-sabredav-Sabre_CardDAV / etc");
}
