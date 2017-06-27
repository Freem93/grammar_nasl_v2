#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-9544.
#

include("compat.inc");

if (description)
{
  script_id(77426);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:49:03 $");

  script_cve_id("CVE-2014-5269");
  script_bugtraq_id(69185);
  script_xref(name:"FEDORA", value:"2014-9544");

  script_name(english:"Fedora 19 : perl-Plack-1.0031-1.fc19 (2014-9544)");
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

  - Fri Aug 8 2014 Ralf Corsepius <corsepiu at
    fedoraproject.org> - 1.0031-1

    - Upstream update.

    - Thu Jan 16 2014 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 1.0030-3

    - Move misplaced %exclude-line from base-package to
      *-Test.

    - Wed Jan 15 2014 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 1.0030-2

    - Split out perl-Plack-Test to avoid dependency on
      Test::More (RHBZ #1052859).

    - Mon Dec 30 2013 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 1.0030-1

    - Upstream update.

    - Wed Sep 18 2013 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 1.0029-1

    - Upstream update.

    - Update BRs.

    - Modernize spec.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1128978"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-August/137099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a9ed73f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-Plack package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Plack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/29");
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
if (rpm_check(release:"FC19", reference:"perl-Plack-1.0031-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Plack");
}
