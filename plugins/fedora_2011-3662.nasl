#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-3662.
#

include("compat.inc");

if (description)
{
  script_id(53000);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2010-4337");
  script_bugtraq_id(45102);
  script_osvdb_id(69533);
  script_xref(name:"FEDORA", value:"2011-3662");

  script_name(english:"Fedora 13 : gnash-0.8.9-1.fc13 (2011-3662)");
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

  - Fri Mar 18 2011 Hicham HAOUARI <hicham.haouari at
    gmail.com> - 1:0.8.9-1

    - Update to 0.8.9 final

    - Sat Mar 12 2011 Hicham HAOUARI <hicham.haouari at
      gmail.com> - 1:0.8.9-0.1.20110312git

    - Switch to 0.8.9 branch

    - Spec cleanup

    - Add extensions

    - Enable testsuite

    - Tue Feb 8 2011 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1:0.8.8-5

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

    - Wed Oct 6 2010 Kevin Kofler <Kevin at
      tigcc.ticalc.org> - 1:0.8.8-4

    - backport 2 upstream commits to make it work with
      libcurl >= 7.21.x (#639737)

    - Sat Oct 2 2010 Kevin Kofler <Kevin at
      tigcc.ticalc.org> - 1:0.8.8-3

    - fix FTBFS (#631181) (fix by Hicham Haouari)

    - Fri Aug 27 2010 Kevin Kofler <Kevin at
      tigcc.ticalc.org> - 1:0.8.8-2

    - fix the check for the docbook2X tools being in Perl

    - Wed Aug 25 2010 Kevin Kofler <Kevin at
      tigcc.ticalc.org> - 1:0.8.8-1.1

    - rebuild for the official release of Boost 1.44.0
      (silent ABI change)

    - Mon Aug 23 2010 Kevin Kofler <Kevin at
      tigcc.ticalc.org> - 1:0.8.8-1

    - update to 0.8.8 (#626352, #574100, #606170)

    - update file list (patch by Jeff Smith)

    - Thu Jul 29 2010 Bill Nottingham <notting at
      redhat.com> - 1:0.8.7-5

    - Rebuilt for boost-1.44, again

    - Tue Jul 27 2010 Bill Nottingham <notting at
      redhat.com> - 1:0.8.7-4

    - Rebuilt for boost-1.44

    - Wed Jul 21 2010 David Malcolm <dmalcolm at redhat.com>
      - 1:0.8.7-3

    - Rebuilt for
      https://fedoraproject.org/wiki/Features/Python_2.7/Mas
      sRebuild

    - Tue Jun 8 2010 Kevin Kofler <Kevin at
      tigcc.ticalc.org> - 1:0.8.7-2

    - -plugin: avoid file (directory) dependency (#601942)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=669851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Features/Python_2.7/MassRebuild"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/056787.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97f73889"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gnash package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC13", reference:"gnash-0.8.9-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnash");
}
