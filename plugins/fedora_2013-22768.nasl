#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-22768.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71250);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 21:47:14 $");

  script_xref(name:"FEDORA", value:"2013-22768");

  script_name(english:"Fedora 19 : lynis-1.3.6-1.fc19 (2013-22768)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - 1.3.6 (2013-12-03)

    New :

  - Support for the dntpd time daemon

    - New Apache test for modules [HTTP-6632]

    - Apache test for mod_evasive [HTTP-6640]

    - Apache test for mod_qos [HTTP-6641]

    - Apache test for mod_spamhaus [HTTP-6642]

    - Apache test for ModSecurity [HTTP-6643]

    - Check for installed package audit tool [PKGS-7398]

    - Added initial support for new pkgng and related tools
      [PKGS-7381]

    - Check for ssh-keyscan binary

    - ZFS support for FreeBSD [FILE-6330]

    - Test for passwordless accounts [AUTH-9283]

    - Initial OS support for DragonFly BSD

    - Initial OS support for TrueOS (FreeBSD based)

    - Initial OS support for elementary OS (Luna)

    - GetHostID for DragonFly, FreeBSD, NetBSD and OpenBSD

    - Check for DHCP client [NETW-3030]

    - Initial support for OSSEC (system integrity)
      [FINT-4328]

    - New parameter --log-file to adjust log file location

    - New function IsRunning() to check status of processes

    - New function RealFilename() to determine file name

    - New function CheckItem() for parsing files

    - New function ReportManual() and ReportException() to
      simplify code

    - New function DirectoryExists() to check existence of a
      directory

    - Support for dntpd [TIME-3104]

      Changes :

  - Extended pf checks for FreeBSD/OpenBSD and others
    [FIRE-4518]

    - Extended test to gather listening network ports for
      Linux [NETW-3012]

    - Adjusted lsof statement to ignore warnings (e.g. fuse)
      [LOGG-2180] [LOGG-2190]

    - Added suggestion for discovered shells on FreeBSD
      [AUTH-9218]

    - Extended core dump test with additional details
      [KRNL-5820]

    - Properly display suggestion if portaudit is not
      installed [PKGS-7382]

    - Ignore message if no packages are installed (pkg_info)
      [PKGS-7320]

    - Also try using apt-check on Debian systems [PKGS-7392]

    - Adjusted logging for RPM binary on systems not using
      it [PKGS-7308]

    - Extended search in cron directories for rdate/ntpdate
      [TIME-3104]

    - Adjusted PHP check to find ini files [PHP-2211]

    - Skip Apache test for NetBSD [HTTP-6622]

    - Skip test http version check for NetBSD [HTTP-6624]

    - Additional check to surpress sort error [HTTP-6626]

    - Improved the way binaries are checked (less disk
      reads)

    - Adjusted ReportWarning() function to skip impact
      rating

    - Improved report on screen by leaving out date/time and
      type

    - Redirect errors while checking for OpenSSL version

    - Extended reporting with firewall status and software

    - Adjusted naming of some operating systems to make them
      more consistent

    - Extended update check by using host binary if dig is
      not installed

    - Count number of installed binaries/packages and report
      them

    - Report about log rotation tool and status

    - Updated man page Belated update after 4 years. Belated
      update after 4 years. Belated update after 4 years.
      Update.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1037866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=469317"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123187.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0501a6a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynis package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lynis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC19", reference:"lynis-1.3.6-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynis");
}
