#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-11795.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85065);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:57:25 $");

  script_cve_id("CVE-2015-0202", "CVE-2015-0248", "CVE-2015-0251");
  script_xref(name:"FEDORA", value:"2015-11795");

  script_name(english:"Fedora 21 : subversion-1.8.13-7.fc21 (2015-11795)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of **Apache
Subversion**, version **1.8.13**.

Three security vulnerabilities are fixed in this update :

  - CVE-2015-0202:
    https://subversion.apache.org/security/CVE-2015-0202-adv
    isory.txt

    - CVE-2015-0248:
      https://subversion.apache.org/security/CVE-2015-0248-a
      dvisory.txt

    - CVE-2015-0251:
      https://subversion.apache.org/security/CVE-2015-0251-a
      dvisory.txt

In addition, the following changes are included in the Subversion
1.8.13 update :

**Client-side bugfixes:**

  - ra_serf: prevent abort of commits that have already
    succeeded

    - ra_serf: support case-insensitivity in HTTP headers

    - better error message if an external is shadowed

    - ra_svn: fix reporting of directory read errors

    - fix a redirect handling bug in 'svn log' over HTTP

    - properly copy tree conflict information

    - fix 'svn patch' output for reordered hunks
      http://subversion.tigris.org/issues/show_bug.cgi?id=45
      33

    - svnrdump load: don't load wrong props with no-deltas
      dump
      http://subversion.tigris.org/issues/show_bug.cgi?id=45
      51

    - fix working copy corruption with relative file
      external
      http://subversion.tigris.org/issues/show_bug.cgi?id=44
      11

    - don't crash if config file is unreadable

    - svn resolve: don't ask a question with only one answer

    - fix assertion failure in svn move

    - working copy performance improvements

    - handle existing working copies which become externals

    - fix recording of WC meta-data for foreign repos copies

    - fix calculating repository path of replaced
      directories

    - fix calculating repository path after commit of
      switched nodes

    - svnrdump: don't provide HEAD+1 as base revision for
      deletes

    - don't leave conflict markers on files that are moved

    - avoid unnecessary subtree mergeinfo recording

    - fix diff of a locally copied directory with props

**Server-side bugfixes:**

  - fsfs: fix a problem verifying pre-1.4 repos used with
    1.8

    - svnadmin freeze: fix memory allocation error

    - svnadmin load: tolerate invalid mergeinfo at r0

    - svnadmin load: strip references to r1 from mergeinfo
      http://subversion.tigris.org/issues/show_bug.cgi?id=45
      38

    - svnsync: strip any r0 references from mergeinfo
      http://subversion.tigris.org/issues/show_bug.cgi?id=44
      76

    - fsfs: reduce memory consumption when operating on dag
      nodes

    - reject invalid get-location-segments requests in
      mod_dav_svn and svnserve

    - mod_dav_svn: reject invalid txnprop change requests

**Client-side and server-side bugfixes:**

  - fix undefined behaviour in string buffer routines

    - fix consistency issues with APR r/w locks on Windows

    - fix occasional SEGV if threads load DSOs in parallel

    - properly duplicate svn error objects

    - fix use-after-free in config parser

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205140"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c4153a0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2015-0202-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2015-0248-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2015-0251-advisory.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"subversion-1.8.13-7.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
