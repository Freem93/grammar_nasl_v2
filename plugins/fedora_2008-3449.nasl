#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3449.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(32197);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/21 22:13:39 $");

  script_cve_id("CVE-2008-1722");
  script_bugtraq_id(28781);
  script_xref(name:"FEDORA", value:"2008-3449");

  script_name(english:"Fedora 7 : cups-1.2.12-11.fc7 (2008-3449)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri May 9 2008 Tim Waugh <twaugh at redhat.com>
    1:1.2.12-11

    - Applied patch to fix CVE-2008-1722 (integer overflow
      in image filter, bug #441692, STR #2790).

  - Tue Apr 1 2008 Tim Waugh <twaugh at redhat.com>
    1:1.2.12-10

    - Applied patch to fix CVE-2008-1373 (GIF overflow, bug
      #438303).

    - Applied patch to fix CVE-2008-0053 (HP-GL/2 input
      processing, bug #438117).

    - Applied patch to prevent heap-based buffer overflow in
      CUPS helper program (bug #436153, CVE-2008-0047, STR
      #2729).

  - Fri Feb 22 2008 Tim Waugh <twaugh at redhat.com>
    1:1.2.12-9

    - Prevent double-free when a browsed class has the same
      name as a printer or vice versa (CVE-2008-0882, bug
      #433758, STR #2656).

  - Mon Nov 12 2007 Tim Waugh <twaugh at redhat.com>
    1:1.2.12-8

    - Fixed CVE-2007-4045 patch; has no effect with shipped
      packages since they are linked with gnutls.

  - LSPP fixes (cupsdSetString/ClearString).

    - Wed Nov 7 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.12-7

    - Applied patch to fix CVE-2007-4045 (bug #250161).

    - Applied patch to fix CVE-2007-4352, CVE-2007-5392 and
      CVE-2007-5393 (bug #345101).

  - Thu Nov 1 2007 Tim Waugh <twaugh at redhat.com>
    1:1.2.12-6

    - Applied patch to fix CVE-2007-4351 (STR #2561, bug
      #361661).

    - Wed Oct 10 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.12-5

    - Use ppdev for parallel port Device ID retrieval (bug
      #311671).

    - Thu Aug 9 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.12-4

    - Applied patch to fix CVE-2007-3387 (bug #251518).

    - Tue Jul 31 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.12-3

    - Better buildroot tag.

    - Moved LSPP access check and security attributes check
      in add_job() to before allocation of the job structure
      (bug #231522).

  - Mon Jul 23 2007 Tim Waugh <twaugh at redhat.com>
    1:1.2.12-2

    - Use kernel support for USB paper-out detection, when
      available (bug #249213).

  - Fri Jul 13 2007 Tim Waugh <twaugh at redhat.com>
    1:1.2.12-1

    - 1.2.12. No longer need adminutil or str2408 patches.

    - Wed Jul 4 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.11-3

    - Better paper-out detection patch still (bug #246222).

    - Fri Jun 29 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.11-2

    - Applied patch to fix group handling in PPDs (bug
      #186231, STR #2408).

    - Wed Jun 27 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.11-1

    - Fixed permissions on classes.conf in the file manifest
      (bug #245748).

    - 1.2.11.

    - Tue Jun 12 2007 Tim Waugh <twaugh at redhat.com>

    - Make the initscript use start priority 56 (bug
      #213828).

    - Mon Jun 11 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.10-12

    - Better paper-out detection patch (bug #241589).

    - Mon May 21 2007 Tim Waugh <twaugh at redhat.com>
      1:1.2.10-11

    - Fixed _cupsAdminSetServerSettings() sharing/shared
      handling (bug #238057).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=441692"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-May/009733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd31df12"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"cups-1.2.12-11.fc7")) flag++;


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
