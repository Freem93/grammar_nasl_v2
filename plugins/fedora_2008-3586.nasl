#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3586.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(32207);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:23:15 $");

  script_cve_id("CVE-2008-1722");
  script_bugtraq_id(28781);
  script_xref(name:"FEDORA", value:"2008-3586");

  script_name(english:"Fedora 8 : cups-1.3.7-2.fc8 (2008-3586)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri May 9 2008 Tim Waugh <twaugh at redhat.com>
    1:1.3.7-2

    - Applied patch to fix CVE-2008-1722 (integer overflow
      in image filter, bug #441692, STR #2790).

  - Fri May 2 2008 Tim Waugh <twaugh at redhat.com>

    - Include the hostname in the charset error (part of bug
      #441719).

    - Thu Apr 10 2008 Tim Waugh <twaugh at redhat.com>

    - Log an error when a client requests a charset other
      than ASCII or UTF-8.

    - Thu Apr 3 2008 Tim Waugh <twaugh at redhat.com>

    - Main package requires exactly-matching libs package.

    - Wed Apr 2 2008 Tim Waugh <twaugh at redhat.com>
      1:1.3.7-1

    - 1.3.7. No longer need str2715, str2727, or
      CVE-2008-0047 patches.

    - Tue Apr 1 2008 Tim Waugh <twaugh at redhat.com>
      1:1.3.6-4

    - Applied patch to fix CVE-2008-1373 (GIF overflow, bug
      #438303).

    - Applied patch to prevent heap-based buffer overflow in
      CUPS helper program (bug #436153, CVE-2008-0047, STR
      #2729).

  - Thu Feb 28 2008 Tim Waugh <twaugh at redhat.com> 1.3.6-3

    - Apply upstream fix for Adobe JPEG files (bug #166460,
      STR #2727).

    - Sat Feb 23 2008 Tim Waugh <twaugh at redhat.com>
      1.3.6-2

    - Fix encoding of job-sheets option (bug #433753, STR
      #2715).

    - Wed Feb 20 2008 Tim Waugh <twaugh at redhat.com>
      1.3.6-1

    - 1.3.6. No longer need str2650, str2664, or str2703
      patches.

    - Tue Feb 12 2008 Tim Waugh <twaugh at redhat.com>
      1.3.5-3

    - Fixed admin.cgi handling of DefaultAuthType (bug
      #432478, STR #2703).

    - Mon Jan 21 2008 Tim Waugh <twaugh at redhat.com>
      1.3.5-2

    - Rebuilt.

    - Thu Jan 10 2008 Tim Waugh <twaugh at redhat.com>

    - Apply patch to fix busy looping in the backends (bug
      #426653, STR #2664).

    - Wed Jan 9 2008 Tim Waugh <twaugh at redhat.com>

    - Apply patch to prevent overlong PPD lines from causing
      failures except in strict mode (bug #405061). Needed
      for compatibility with older versions of foomatic
      (e.g. Red Hat Enterprise Linux 3/4).

  - Applied upstream patch to fix cupsctl --remote-any (bug
    #421411, STR #2650).

    - Thu Jan 3 2008 Tim Waugh <twaugh at redhat.com>
      1.3.5-1

    - 1.3.5. No longer need str2600, CVE-2007-4352,5392,5393
      patches.

    - Efficiency fix for pstoraster (bug #416871).

    - Fri Nov 30 2007 Tim Waugh <twaugh at redhat.com>

    - CVE-2007-4045 patch is not necessarily because
      cupsd_client_t objects are not moved in array
      operations, only pointers to them.

  - Tue Nov 27 2007 Tim Waugh <twaugh at redhat.com>

    - Updated to improved dnssd backend from Till Kamppeter.

    - Don't undo the util.c parts of STR #2537.

    - Tue Nov 20 2007 Tim Waugh <twaugh at redhat.com>
      1:1.3.4-4

    - Added fix for STR #2600 in which cupsd can crash from
      a NULL dereference with LogLevel debug2 (bug #385631).

  - Mon Nov 12 2007 Tim Waugh <twaugh at redhat.com>
    1:1.3.4-3

    - Fixed CVE-2007-4045 patch; has no effect with shipped
      packages since they are linked with gnutls.

  - Temporarily undo STR #2537 change so that non-UTF-8
    requests are not rejected (bug #378211).

  - LSPP cupsdSetString/ClearString fixes (bug #378451).

[plus 6 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=441692"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-May/009720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e86d829"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/11");
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
if (rpm_check(release:"FC8", reference:"cups-1.3.7-2.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups");
}
