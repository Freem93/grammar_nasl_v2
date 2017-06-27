#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-9565.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47600);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2008-5983", "CVE-2010-1634", "CVE-2010-2089");
  script_bugtraq_id(40370, 40862, 40863);
  script_xref(name:"FEDORA", value:"2010-9565");

  script_name(english:"Fedora 12 : python-2.6.2-8.fc12 (2010-9565)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Jun 4 2010 David Malcolm <dmalcolm at redhat.com> -
    2.6.2-8

    - ensure that the compiler is invoked with '-fwrapv'
      (rhbz#594819)

    - CVE-2010-1634: fix various integer overflow checks in
      the audioop module (patch 113)

  - CVE-2010-2089: further checks within the audioop module
    (patch 114)

    - CVE-2008-5983: the new PySys_SetArgvEx entry point
      from r81399 (patch 115)

    - Fri Mar 12 2010 David Malcolm <dmalcolm at redhat.com>
      - 2.6.2-7

    - document all patches, and remove the commented-out
      ones

    - Address some of the issues identified in package
      review (bug 226342) :

    - update libs requirement on base package to use %{name}
      for consistency's sake

  - convert from backticks to $() syntax throughout

    - wrap value of LD_LIBRARY_PATH in quotes

    - convert '/usr/bin/find' requirement to 'findutils'

    - remove trailing periods from summaries of subpackages

    - fix spelling mistake in description of -test
      subpackage

    - convert usage of $$RPM_BUILD_ROOT to %{buildroot}
      throughout, for stylistic consistency

  - supply dirmode arguments to defattr directives

    - replace references to /usr with %{_prefix}; replace
      references to /usr/include with %{_includedir}

  - fixup the build when __python_ver is set (Zach Sadecki;
    bug 533989); use pybasever in the files section

  - Mon Jan 25 2010 David Malcolm <dmalcolm at redhat.com> -
    2.6.2-6

    - update python-2.6.2-config.patch to remove downstream
      customization of build of pyexpat and elementtree
      modules

  - add patch adapted from upstream (patch 3) to add support
    for building against system expat; add
    --with-system-expat to 'configure' invocation (patch 3)

  - remove embedded copy of expat from source tree during
    'prep'

    - Mon Jan 25 2010 David Malcolm <dmalcolm at redhat.com>
      - 2.6.2-5

    - replace 'define' with 'global' throughout

    - introduce macros for 3 directories, replacing expanded
      references throughout: %{pylibdir}, %{dynload_dir},
      %{site_packages}

  - explicitly list all lib-dynload files, rather than
    dynamically gathering the payload into a temporary text
    file, so that we can be sure what we are shipping;
    remove now-redundant testing for presence of certain .so
    files

  - remove embedded copy of libffi and zlib from source tree
    before building

    - Mon Jan 25 2010 David Malcolm <dmalcolm at redhat.com>
      - 2.6.2-4

    - change python-2.6.2-config.patch to remove our
      downstream change to curses configuration in
      Modules/Setup.dist, so that the curses modules are
      built using setup.py with the downstream default
      (linking against libncursesw.so, rather than
      libncurses.so), rather than within the Makefile; add a
      test to %install to verify the dso files that the
      curses module is linked against the correct DSO (bug
      539917; changes _cursesmodule.so -> _curses.so)

  - Fri Jan 8 2010 David Malcolm <dmalcolm at redhat.com> -
    2.6.2-3

    - fix Lib/SocketServer.py to avoid trying to use
      non-existent keyword args for os.waitpid (patch 52,
      rhbz:552404, Adrian Reber)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=482814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=590690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=598197"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/043726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f0e5c1a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/06");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"python-2.6.2-8.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
