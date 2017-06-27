#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-4038.
#

include("compat.inc");

if (description)
{
  script_id(53201);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:05:54 $");

  script_xref(name:"FEDORA", value:"2011-4038");

  script_name(english:"Fedora 15 : roundcubemail-0.5.1-1.fc15 (2011-4038)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Roundcube Webmail upstream has released v0.5.1 version: [1]
http://trac.roundcube.net/wiki/Changelog

which adds one security hardening: 1), Security: add optional referer
check to prevent CSRF in GET requests Relevant patches: [2]
http://trac.roundcube.net/changeset/4503 [3]
http://trac.roundcube.net/changeset/4504

and fixes two security flaws: 2), Security: protect login form
submission from CSRF Relevant patch: [4]
http://trac.roundcube.net/changeset/4490 3), Security: prevent from
relaying malicious requests through modcss.inc Relevant patch: [5]
http://trac.roundcube.net/changeset/4488

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://roundcube.net/news"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/news/?group_id=139281&id=297236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/changeset/4488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/changeset/4490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/changeset/4503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/changeset/4504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/wiki/Changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2011/03/24/3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/056917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9143218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"roundcubemail-0.5.1-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
