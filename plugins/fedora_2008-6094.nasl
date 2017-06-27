#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6094.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33413);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:23:16 $");

  script_cve_id("CVE-2008-2376");
  script_xref(name:"FEDORA", value:"2008-6094");

  script_name(english:"Fedora 8 : ruby-1.8.6.230-4.fc8 (2008-6094)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Jul 1 2008 Akira TAGOH <tagoh at redhat.com> -
    1.8.6.230-4

    - Backported from upstream SVN to fix a segfault issue
      with Array#fill.

    - Mon Jun 30 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.230-3

    - Backported from upstream SVN to fix a segfault issue.
      (#452825)

    - Backported from upstream SVN to fix an integer
      overflow in rb_ary_fill.

    - Wed Jun 25 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.230-2

    - Fix a segfault issue. (#452798)

    - Tue Jun 24 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.230-1

    - New upstream release.

    - Security fixes. (#452293)

    - CVE-2008-1891: WEBrick CGI source disclosure.

    - CVE-2008-2662: Integer overflow in
      rb_str_buf_append().

    - CVE-2008-2663: Integer overflow in rb_ary_store().

    - CVE-2008-2664: Unsafe use of alloca in
      rb_str_format().

    - CVE-2008-2725: Integer overflow in rb_ary_splice().

    - CVE-2008-2726: Integer overflow in rb_ary_splice().

    - ruby-1.8.6.111-CVE-2007-5162.patch: removed.

    - Tue Mar 4 2008 Akira TAGOH <tagoh at redhat.com> -
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

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=453589"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e704a93"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"ruby-1.8.6.230-4.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
