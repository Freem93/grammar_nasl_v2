#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3399.
#

include("compat.inc");

if (description)
{
  script_id(32105);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_cve_id("CVE-2008-1927");
  script_bugtraq_id(28928);
  script_xref(name:"FEDORA", value:"2008-3399");

  script_name(english:"Fedora 7 : perl-5.8.8-29.fc7 (2008-3399)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Apr 29 2008 Marcela Maslanova <mmaslano at
    redhat.com> - 4:5.8.8-29

    - CVE-2008-1927 buffer overflow, when unicode character
      is used.

    - Thu Jan 31 2008 Tom 'spot' Callaway <tcallawa at
      redhat.com> - 4:5.8.8-28

    - create /usr/lib/perl5/vendor_perl/5.8.8/auto and own
      it in base perl (resolves bugzilla 214580)

  - Mon Nov 26 2007 Tom 'spot' Callaway <tcallawa at
    redhat.com> - 4:5.8.8-27

    - break dep loop, fix bugzilla 397881

    - Mon Nov 12 2007 Tom 'spot' Callaway <tcallawa at
      redhat.com> - 4:5.8.8-26

    - fix for CVE-2007-5116

    - Thu Oct 25 2007 Tom 'spot' Callaway <tcallawa at
      redhat.com> - 4:5.8.8-25

    - patch from perl bug 24254, fix for RH bz 114271

    - Mon Oct 1 2007 Tom 'spot' Callaway <tcallawa at
      redhat.com> - 4:5.8.8-24

    - update DB_File to 1.815

    - Sat Aug 18 2007 Stepan Kasal <skasal at redhat.com> -
      4:5.8.8-23

    - Remove unnnecessary parens from the License tags.

    - Sat Aug 18 2007 Stepan Kasal <skasal at redhat.com> -
      4:5.8.8-22

    - Fix the License: tags.

    - Fri Aug 17 2007 Stepan Kasal <skasal at redhat.com> -
      4:5.8.8-21

    - Apply patch to skip hostname tests, since hostname
      lookup isn't available in Fedora buildroots by design.

  - Fri Aug 17 2007 Stepan Kasal <skasal at redhat.com> -
    4:5.8.8-20

    - perl rpm requires the corresponding version of
      perl-libs rpm

    - Resolves: rhbz#240540

    - Fri Jun 22 2007 Robin Norwood <rnorwood at redhat.com>
      - 4:5.8.8-19

    - Resolves: rhbz#196836

    - Apply upstream patch #28775, which fixes an issue
      where reblessing overloaded objects incurs significant
      performance penalty

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=443928"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cb594bb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/01");
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
if (rpm_check(release:"FC7", reference:"perl-5.8.8-29.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
