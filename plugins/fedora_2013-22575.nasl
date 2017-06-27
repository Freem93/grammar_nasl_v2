#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-22575.
#

include("compat.inc");

if (description)
{
  script_id(71775);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 21:47:13 $");

  script_cve_id("CVE-2013-4505", "CVE-2013-4558");
  script_bugtraq_id(63966, 63981);
  script_xref(name:"FEDORA", value:"2013-22575");

  script_name(english:"Fedora 20 : subversion-1.8.5-2.fc20 (2013-22575)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of Apache Subversion
1.8, version 1.8.5. Two security fixes are included :

mod_dontdothat allows you to block update REPORT requests against
certain paths in the repository. It expects the paths in the REPORT
request to be absolute URLs. Serf based clients send relative URLs
instead of absolute URLs in many cases. As a result these clients are
not blocked as configured by mod_dontdothat. (CVE-2013-4505)

When SVNAutoversioning is enabled via 'SVNAutoversioning on' commits
can be made by single HTTP requests such as MKCOL and PUT. If
Subversion is built with assertions enabled any such requests that
have non-canonical URLs, such as URLs with a trailing /, may trigger
an assert. An assert will cause the Apache process to abort.
(CVE-2013-4558)

Other fixes included in this update are as follows :

Client-side bugfixes :

  - fix externals that point at redirected locations

    - diff: fix assertion with move inside a copy

Server-side bugfixes :

  - mod_dav_svn: Prevent crashes with some 3rd party modules

    - mod_authz_svn: fix crash of mod_authz_svn with invalid
      config

    - hotcopy: fix hotcopy losing revprop files in packed
      repos

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1033431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1033995"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/125452.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7663a73a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"subversion-1.8.5-2.fc20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
