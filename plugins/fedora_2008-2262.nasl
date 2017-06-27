#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-2262.
#

include("compat.inc");

if (description)
{
  script_id(31371);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-0983", "CVE-2008-1111");
  script_bugtraq_id(27943, 28100);
  script_xref(name:"FEDORA", value:"2008-2262");

  script_name(english:"Fedora 7 : lighttpd-1.4.18-3.fc7 (2008-2262)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Mar 4 2008 Matthias Saou <http://freshrpms.net/>
    1.4.18-3

    - Include patch for CVE-2008-0983 (crash when low on
      file descriptors).

    - Include patch for CVE-2008-1111 (cgi source
      disclosure).

    - Tue Oct 16 2007 Matthias Saou <http://freshrpms.net/>
      1.4.18-2

    - Include mod_geoip additional source, make it an
      optional sub-package.

    - Reorder sub-packages alphabetically in spec file.

    - Mon Sep 10 2007 Matthias Saou <http://freshrpms.net/>
      1.4.18-1

    - Update to 1.4.18.

    - Include newly installed lighttpd-angel ('angel'
      process meant to always run as root and restart
      lighttpd when it crashes, spawn processes on SIGHUP),
      but it's in testing stage and must be run with -D for
      now.

  - Wed Sep 5 2007 Matthias Saou <http://freshrpms.net/>
    1.4.17-1

    - Update to 1.4.17.

    - Update defaultconf patch to match new example
      configuration.

    - Include patch to fix log file rotation with
      max-workers set (trac #902).

    - Add /var/run/lighttpd/ directory where to put fastcgi
      sockets.

    - Thu Aug 23 2007 Matthias Saou <http://freshrpms.net/>
      1.4.16-3

    - Add /usr/bin/awk build requirement, used to get
      LIGHTTPD_VERSION_ID.

    - Wed Aug 22 2007 Matthias Saou <http://freshrpms.net/>
      1.4.16-2

    - Rebuild to fix wrong execmem requirement on ppc32.

    - Thu Jul 26 2007 Matthias Saou <http://freshrpms.net/>
      1.4.16-1

    - Update to 1.4.16 security fix release.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://freshrpms.net/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=434163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=435805"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008501.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?615faf52"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"lighttpd-1.4.18-3.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd");
}
