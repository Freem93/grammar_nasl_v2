#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-2458.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31433);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:13:38 $");

  script_cve_id("CVE-2008-1145");
  script_bugtraq_id(28123);
  script_xref(name:"FEDORA", value:"2008-2458");

  script_name(english:"Fedora 7 : ruby-1.8.6.114-1.fc7 (2008-2458)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Mar 4 2008 Akira TAGOH <tagoh at redhat.com> -
    1.8.6.114-1

    - Security fix for CVE-2008-1145.

    - Improve a spec file. (#226381)

    - Correct License tag.

    - Fix a timestamp issue.

    - Own a arch-specific directory.

    - Tue Feb 19 2008 Fedora Release Engineering <rel-eng at
      fedoraproject.org> - 1.8.6.111-9

    - Autorebuild for GCC 4.3

    - Tue Feb 19 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.111-8

    - Rebuild for gcc-4.3.

    - Tue Jan 15 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.111-7

    - Revert the change of libruby-static.a. (#428384)

    - Fri Jan 11 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.111-6

    - Fix an unnecessary replacement for shebang. (#426835)

    - Fri Jan 4 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.111-5

    - Rebuild.

    - Fri Dec 28 2007 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.111-4

    - Clean up again.

    - Fri Dec 21 2007 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.111-3

    - Clean up the spec file.

    - Remove ruby-man-1.4.6 stuff. this is entirely the
      out-dated document. this could be replaced by ri.

  - Disable the static library building.

    - Tue Dec 4 2007 Release Engineering <rel-eng at
      fedoraproject dot org> - 1.8.6.111-2

    - Rebuild for openssl bump

    - Wed Oct 31 2007 Akira TAGOH <tagoh at redhat.com>

    - Fix the dead link.

    - Mon Oct 29 2007 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.111-1

    - New upstream release.

    - ruby-1.8.6.111-CVE-2007-5162.patch: Update a bit with
      backporting the changes at trunk to enable the fix
      without any modifications on the users' scripts. Note
      that Net::HTTP#enable_post_connection_check isn't
      available anymore. If you want to disable this
      post-check, you should give OpenSSL::SSL::VERIFY_NONE
      to Net::HTTP#verify_mode= instead of.

  - Mon Oct 15 2007 Akira TAGOH <tagoh at redhat.com> -
    1.8.6.110-2

    - Enable pthread support for ppc too. (#201452)

    - Fix unexpected dependencies appears in ruby-libs.
      (#253325)

    - Wed Oct 10 2007 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.110-1

    - New upstream release.

    - ruby-r12567.patch: removed.

    - ruby-1.8.6-CVE-2007-5162.patch: security fix for
      Net::HTTP that is insufficient verification of SSL
      certificate.

  - Thu Aug 23 2007 Akira TAGOH <tagoh at redhat.com> -
    1.8.6.36-4

    - Rebuild

    - Fri Aug 10 2007 Akira TAGOH <tagoh at redhat.com>

    - Update License tag.

    - Wed Jul 25 2007 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.36-3

    - ruby-r12567.patch: backport patch from upstream svn to
      get rid of the unnecessary declarations. (#245446)

  - Fri Jul 20 2007 Akira TAGOH <tagoh at redhat.com> -
    1.8.6.36-2

    - New upstream release.

    - Fix Etc::getgrgid to get the correct gid as requested.
      (#236647)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=435902"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44661efd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"ruby-1.8.6.114-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
