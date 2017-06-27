#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1278.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24056);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-1278");

  script_name(english:"Fedora Core 6 : elinks-0.11.1-5.1 (2006-1278)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Nov 21 2006 Karel Zak <kzak at redhat.com>
    0.11.1-5.1

    - fix #215734: CVE-2006-5925 elinks smb protocol
      arbitrary file access

    - Wed Oct 11 2006 Karel Zak <kzak at redhat.com>
      0.11.1-5

    - fix #210103 - elinks crashes when given bad HTTP_PROXY

    - Wed Jul 12 2006 Jesse Keating <jkeating at redhat.com>
      - 0.11.1-4.1

    - rebuild

    - Mon Jun 12 2006 Karel Zak <kzak at redhat.com>
      0.11.1-4

    - improved negotiate-auth patch (faster now)

    - Fri Jun 9 2006 Karel Zak <kzak at redhat.com> 0.11.1-3

    - added negotiate-auth (GSSAPI) support -- EXPERIMENTAL!

    - Mon May 29 2006 Karel Zak <kzak at redhat.com>
      0.11.1-2

    - update to new upstream version

    - Wed May 17 2006 Karsten Hopp <karsten at redhat.de>
      0.11.0-3

    - add buildrequires bzip2-devel,
      expat-devel,libidn-devel

    - Fri Feb 10 2006 Jesse Keating <jkeating at redhat.com>
      - 0.11.0-2.2

    - bump again for double-long bug on ppc(64)

    - Tue Feb 7 2006 Jesse Keating <jkeating at redhat.com>
      - 0.11.0-2.1

    - rebuilt for new gcc4.1 snapshot and glibc changes

    - Tue Jan 10 2006 Karel Zak <kzak at redhat.com>
      0.11.0-2

    - use upstream version of srcdir.patch

    - Tue Jan 10 2006 Karel Zak <kzak at redhat.com>
      0.11.0-1

    - update to new upstream version

    - fix 0.11.0 build system (srcdir.patch)

    - regenerate patches: elinks-0.11.0-getaddrinfo.patch,
      elinks-0.11.0-ssl-noegd.patch,
      elinks-0.11.0-sysname.patch, elinks-0.11.0-union.patch

  - Fri Dec 9 2005 Jesse Keating <jkeating at redhat.com>
    0.10.6-2.1

    - rebuilt

    - Wed Nov 9 2005 Karel Zak <kzak at redhat.com> 0.10.6-2

    - rebuild (against new openssl)

    - Thu Sep 29 2005 Karel Zak <kzak at redhat.com>
      0.10.6-1

    - update to new upstream version

    - Tue May 17 2005 Karel Zak <kzak at redhat.com>
      0.10.3-3

    - fix #157300 - Strange behavior on ppc64 (patch by
      Miloslav Trmac)

    - Tue May 10 2005 Miloslav Trmac <mitr at redhat.com> -
      0.10.3-2

    - Fix checking for numeric command prefix (#152953,
      patch by Jonas Fonseca)

    - Fix invalid C causing assertion errors on ppc and ia64
      (#156647)

    - Mon Mar 21 2005 Karel Zak <kzak at redhat.com>
      0.10.3-1

    - sync with upstream; stable 0.10.3

    - Sat Mar 5 2005 Karel Zak <kzak at redhat.com> 0.10.2-2

    - rebuilt

    - Tue Feb 8 2005 Karel Zak <kzak at redhat.com> 0.10.2-1

    - sync with upstream; stable 0.10.2

    - Fri Jan 28 2005 Karel Zak <kzak at redhat.com>
      0.10.1-1

    - sync with upstream; stable 0.10.1

    - Thu Oct 14 2004 Karel Zak <kzak at redhat.com> 0.9.2-2

    - the 'Linux' driver seems better than 'VT100' for xterm
      (#128105)

    - Wed Oct 6 2004 Karel Zak <kzak at redhat.com> 0.9.2-1

[plus 117 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-November/000946.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00bdc36c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elinks and / or elinks-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elinks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elinks-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/21");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"elinks-0.11.1-5.1")) flag++;
if (rpm_check(release:"FC6", reference:"elinks-debuginfo-0.11.1-5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elinks / elinks-debuginfo");
}
