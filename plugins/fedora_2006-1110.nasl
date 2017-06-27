#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1110.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24039);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_bugtraq_id(20777);
  script_xref(name:"FEDORA", value:"2006-1110");

  script_name(english:"Fedora Core 5 : ruby-1.8.5-1.fc5 (2006-1110)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Oct 27 2006 Akira TAGOH <tagoh at redhat.com> -
    1.8.5-1

    - security fix release.

    - ruby-1.8.5-cgi-CVE-2006-5467.patch: fix a CGI
      multipart parsing bug that causes the denial of
      service. (#212396)

  - backport fixes from devel.

    - fixed rbconfig.rb to refer to DESTDIR for sitearchdir.
      (#207311)

    - updates to 1.8.5

    - removed the unnecessary patches:
      ruby-1.8.4-no-eaccess.patch,
      ruby-1.8.4-64bit-pack.patch,
      ruby-1.8.4-fix-insecure-dir-operation.patch,
      ruby-1.8.4-fix-insecure-regexp-modification.patch,
      ruby-1.8.4-fix-alias-safe-level.patch.

  - build with --enable-pthread except on ppc.

    - ruby-1.8.5-hash-memory-leak.patch: backported from CVS
      to fix a memory leak on Hash. [ruby-talk:211233]

  - owns sitearchdir. (#201208)

    - Thu Jul 20 2006 Akira TAGOH <tagoh at redhat.com> -
      1.8.4-8

    - security fixes [CVE-2006-3694]

    - ruby-1.8.4-fix-insecure-dir-operation.patch :

    - ruby-1.8.4-fix-insecure-regexp-modification.patch:
      fixed the insecure operations in the certain
      safe-level restrictions. (#199538)

  - ruby-1.8.4-fix-alias-safe-level.patch: fixed to not
    bypass the certain safe-level restrictions. (#199543)

  - Mon Jun 19 2006 Akira TAGOH <tagoh at redhat.com> -
    1.8.4-7.fc5

    - fixed the wrong file list again. moved tcltk library
      into ruby-tcltk. (#195872)

  - Thu Jun 8 2006 Akira TAGOH <tagoh at redhat.com> -
    1.8.4-5.fc5

    - ruby-deprecated-search-path.patch: applied to add more
      search path for backward compatibility.

  - added byacc to BuildReq.

    - exclude ppc64 to make ruby-mode package. right now
      emacs.ppc64 isn't provided and buildsys became much
      stricter.

  - Wed May 17 2006 Akira TAGOH <tagoh at redhat.com> -
    1.8.4-4.fc5

    - correct sitelibdir. (#184198)

    - ruby-rubyprefix.patch: moved all arch-independent
      modules under /usr/lib/ruby and keep arch-dependent
      modules under /usr/lib64/ruby for 64bit archs. so
      'rubylibdir', 'sitelibdir' and 'sitedir' in
      Config::CONFIG points to the kind of /usr/lib/ruby
      now. (#184199)

  - ruby-deprecated-search-path.patch: added the deprecated
    installation paths to the search path for the backward
    compatibility.

  - added a Provides: ruby(abi) to ruby-libs.

    - ruby-1.8.4-64bit-pack.patch: backport patch from
      upstream to fix unpack('l') not working on 64bit arch
      and integer overflow on template 'w'. (#189350)

  - updated License tag to be more comfortable, and with a
    pointer to get more details, like Python package does.
    (#179933)

  - clean up.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-October/000718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54bfc383"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"ruby-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-debuginfo-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-devel-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-docs-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-irb-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-libs-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-mode-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-rdoc-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-ri-1.8.5-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"ruby-tcltk-1.8.5-1.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-docs / ruby-irb / etc");
}
