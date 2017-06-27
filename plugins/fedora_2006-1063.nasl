#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1063.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24037);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-1063");

  script_name(english:"Fedora Core 6 : mutt-1.4.2.2-3.fc6 (2006-1063)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Oct 24 2006 Miroslav Lichvar <mlichvar at
    redhat.com> 5:1.4.2.2-3

    - fix insecure temp file creation on NFS (#211085,
      CVE-2006-5297)

    - Thu Aug 3 2006 Miroslav Lichvar <mlichvar at
      redhat.com> 5:1.4.2.2-2

    - fix a SASL authentication bug (#199591)

    - Mon Jul 17 2006 Miroslav Lichvar <mlichvar at
      redhat.com> 5:1.4.2.2-1

    - update to 1.4.2.2

    - fix directories in manual.txt (#162207)

    - drop bcc patch (#197408)

    - don't package flea

    - Wed Jul 12 2006 Jesse Keating <jkeating at redhat.com>
      - 5:1.4.2.1-7.1

    - rebuild

    - Thu Jun 29 2006 Miroslav Lichvar <mlichvar at
      redhat.com> 5:1.4.2.1-7

    - fix a buffer overflow when processing IMAP namespace
      (#197152, CVE-2006-3242)

    - Fri Feb 10 2006 Jesse Keating <jkeating at redhat.com>
      - 5:1.4.2.1-6.2.1

    - bump again for double-long bug on ppc(64)

    - Tue Feb 7 2006 Jesse Keating <jkeating at redhat.com>
      - 5:1.4.2.1-6.2

    - rebuilt for new gcc4.1 snapshot and glibc changes

    - Fri Dec 9 2005 Jesse Keating <jkeating at redhat.com>

    - rebuilt

    - Wed Nov 9 2005 Bill Nottingham <notting at redhat.com>
      5:1.4.2.1-6

    - rebuild against new ssl libs

    - Thu Oct 27 2005 Bill Nottingham <notting at
      redhat.com> 5:1.4.2.1-5

    - add patch from 1.5 branch to fix SASL logging
      (#157251, #171528)

    - Fri Aug 26 2005 Bill Nottingham <notting at
      redhat.com> 5:1.4.2.1-3

    - add patch from 1.5 branch to fix base64 decoding
      (#166718)

    - Mon Mar 7 2005 Bill Nottingham <notting at redhat.com>
      5:1.4.2.1-2

    - rebuild against new openssl

    - fix build with gcc4

    - Thu Jan 27 2005 Bill Nottingham <notting at
      redhat.com> 5:1.4.2.1-1

    - update to 1.4.2.1 (#141007, <moritz at barsnick.net>)

    - include a /etc/Muttrc.local for site config (#123109)

    - add <f2> as a additional help key for terminals that
      use <f1> internally (#139277)

  - Wed Sep 15 2004 Nalin Dahyabhai <nalin at redhat.com>
    5:1.4.1-10

    - expect the server to prompt for additional auth data
      if we have some to send (#129961, upstream #1845)

  - use 'pop' as the service name instead of 'pop-3' when
    using SASL for POP, per rfc1734

  - Fri Aug 13 2004 Bill Nottingham <notting at redhat.com>
    5:1.4.1-9

    - set write_bcc to no by default (since we ship exim)

    - build against sasl2 (#126724)

    - Mon Jun 28 2004 Bill Nottingham <notting at
      redhat.com>

    - remove autosplat patch (#116769)

    - Tue Jun 15 2004 Elliot Lee <sopwith at redhat.com>

    - rebuilt

    - Tue Jun 8 2004 Bill Nottingham <notting at redhat.com>
      5:1.4.1-7

    - link urlview against ncursesw (fixes #125530,
      indirectly)

    - Fri Feb 13 2004 Elliot Lee <sopwith at redhat.com>

    - rebuilt

    - Tue Jan 27 2004 Bill Nottingham <notting at
      redhat.com> 5:1.4.1-5

[plus 179 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-October/000686.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a546de0a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mutt and / or mutt-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mutt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mutt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/24");
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
if (rpm_check(release:"FC6", reference:"mutt-1.4.2.2-3.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"mutt-debuginfo-1.4.2.2-3.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mutt / mutt-debuginfo");
}
