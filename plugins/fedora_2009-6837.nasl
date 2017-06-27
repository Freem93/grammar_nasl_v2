#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-6837.
#

include("compat.inc");

if (description)
{
  script_id(39508);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:50:38 $");

  script_xref(name:"FEDORA", value:"2009-6837");

  script_name(english:"Fedora 10 : rt3-3.8.2-8.fc10 (2009-6837)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Jun 19 2009 Ralf Corsepius <corsepiu at
    fedoraproject.org> - 3.8.2-8

    - Address BZ #506885 (BZ #506236).

    - Remove rt-3.4.1-I18N.diff.

    - Fri Apr 24 2009 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.2-7

    - README.fedora.in: Add --dba root to rt-setup-database
      (BZ #488621).

    - R: perl(XML::RSS) (BZ #496720).

    - Wed Feb 18 2009 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.2-5

    - Add R: perl(Class::Accessor::Fast),
      perl(Exception::Class::Base),
      perl(HTML::Mason::Request),
      perl(Net::Server::PreFork).

  - Thu Feb 5 2009 Ralf Corsepius <corsepiu at
    fedoraproject.org> - 3.8.2-4

    - Stop filtering perl(Test::Email).

    - Add perl(:MODULE_COMPAT ...) to perl-RT-Test.

    - Sat Jan 24 2009 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.2-3

    - Fix date in changelog entry.

    - Sat Jan 24 2009 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.2-2

    - Filter out R: perl(Test::Email).

    - Add perl-RT-Test package.

    - Activate --with devel_mode.

    - Don't pass --enable/disable-devel-mode to configure.

    - Add Explicit check for devel-mode deps.

    - Fri Jan 23 2009 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.2-1

    - Upstream update.

    - Preps to add a perl-RT-Test package.

    - Sun Nov 30 2008 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.1-2

    - Fix rt3-mailgate's %defattr(-,root,root,-).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=506885"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/025515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19301dc0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rt3 package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rt3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"rt3-3.8.2-8.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rt3");
}
