#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6033.
#

include("compat.inc");

if (description)
{
  script_id(33408);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:23:16 $");

  script_cve_id("CVE-2008-2376");
  script_bugtraq_id(30036);
  script_xref(name:"FEDORA", value:"2008-6033");

  script_name(english:"Fedora 9 : ruby-1.8.6.230-4.fc9 (2008-6033)");
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

    - Fix a segfault issue. (#452809)

    - Tue Jun 24 2008 Akira TAGOH <tagoh at redhat.com> -
      1.8.6.230-1

    - New upstream release.

    - Security fixes. (#452294).

    - CVE-2008-1891: WEBrick CGI source disclosure.

    - CVE-2008-2662: Integer overflow in
      rb_str_buf_append().

    - CVE-2008-2663: Integer overflow in rb_ary_store().

    - CVE-2008-2664: Unsafe use of alloca in
      rb_str_format().

    - CVE-2008-2725: Integer overflow in rb_ary_splice().

    - CVE-2008-2726: Integer overflow in rb_ary_splice().

    - ruby-1.8.6.111-CVE-2007-5162.patch: removed.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=453589"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/011992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76188a54"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/03");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"ruby-1.8.6.230-4.fc9")) flag++;


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
