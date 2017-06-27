#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-17439.
#

include("compat.inc");

if (description)
{
  script_id(50683);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/21 05:48:02 $");

  script_cve_id("CVE-2010-0405");
  script_bugtraq_id(43331);
  script_osvdb_id(68167);
  script_xref(name:"FEDORA", value:"2010-17439");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"Fedora 13 : clamav-0.96.4-1300.fc13 (2010-17439)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"----------------------------------------------------------------------
---------- ChangeLog :

  - Sun Oct 31 2010 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de> - 0.96.4-1300

    - updated to 0.96.4

    - execute 'make check' (#640347) but ignore errors for
      now because four checks are failing on f13

  - Wed Sep 29 2010 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de>

    - lowered stop priority of sysv initscripts (#629435)

    - Wed Sep 22 2010 Enrico Scholz <enrico.scholz at
      informatik.tu-chemnitz.de> - 0.96.3-1300

    - updated to 0.96.3

    - fixes CVE-2010-0405 in shipped bzlib.c copy

    - Sun Aug 15 2010 Enrico Scholz <enrico.scholz at
      informatik.tu-chemnitz.de> - 0.96.2-1300

    - updated to 0.96.2

    - rediffed patches

    - removed the -jit-disable patch which is replaced
      upstream by a more detailed configuration option.

  - Wed Aug 11 2010 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de>

    - use 'groupmems', not 'usermod' to add a user to a
      group because 'usermod' does not work when user does
      not exist in local /etc/passwd

  - Tue Jun 1 2010 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de> - 0.96.1-1400

    - updated to 0.96.1

    - applied upstream patch which allows to disable JIT
      compiler (#573191)

    - disabled JIT compiler by default

    - removed explicit 'pkgconfig' requirements in -devel
      (#533956)

    - added some BRs

    - rediffed patches

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=627882"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/051278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b3e4869"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"clamav-0.96.4-1300.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
