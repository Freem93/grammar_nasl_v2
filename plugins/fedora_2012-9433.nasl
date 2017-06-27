#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-9433.
#

include("compat.inc");

if (description)
{
  script_id(59951);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2012-3356", "CVE-2012-3357");
  script_bugtraq_id(54197, 54199);
  script_xref(name:"FEDORA", value:"2012-9433");

  script_name(english:"Fedora 17 : viewvc-1.1.15-1.fc17 (2012-9433)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Version 1.1.14 (released 12-Jun-2012)

  - fix annotation of svn files with non-URI-safe paths
    (issue #504)

    - handle file:/// Subversion rootpaths as local roots
      (issue #446)

    - fix bug caused by trying to case-normalize anon
      usernames (issue #505)

    - speed up log handling by reusing tokenization results
      (issue #506)

    - add support for custom review log markup rules (issue
      #429)

Version 1.1.15 (released 22-Jun-2012)

  - security fix: complete authz support for remote SVN
    views (issue #353)

    - security fix: log msg leak in SVN revision view with
      unreadable copy source

    - fix several instances of incorrect information in
      remote SVN views

    - increase performance of some revision metadata lookups
      in remote SVN views

    - fix RSS feed regression introduced in 1.1.14

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=835293"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-July/083728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2f572fd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected viewvc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:viewvc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"viewvc-1.1.15-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "viewvc");
}
