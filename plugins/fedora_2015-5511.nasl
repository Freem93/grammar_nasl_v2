#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-5511.
#

include("compat.inc");

if (description)
{
  script_id(82961);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 23:14:51 $");

  script_xref(name:"FEDORA", value:"2015-5511");

  script_name(english:"Fedora 22 : mediawiki-1.24.2-1.fc22 (2015-5511)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes since 1.24.1

  - (bug T85848, bug T71210) SECURITY: Don't parse XMP
    blocks that contain XML entities, to prevent various DoS
    attacks.

    - (bug T85848) SECURITY: Don't allow directly calling
      Xml::isWellFormed, to reduce likelihood of DoS.

    - (bug T88310) SECURITY: Always expand xml entities when
      checking SVG's.

    - (bug T73394) SECURITY: Escape > in
      Html::expandAttributes to prevent XSS.

    - (bug T85855) SECURITY: Don't execute another user's
      CSS or JS on preview.

    - (bug T64685) SECURITY: Allow setting maximal password
      length to prevent DoS when using PBKDF2.

    - (bug T85349, bug T85850, bug T86711) SECURITY:
      Multiple issues fixed in SVG filtering to prevent XSS
      and protect viewer's privacy.

    - Fix case of SpecialAllPages/SpecialAllMessages in
      SpecialPageFactory to fix loading these special pages
      when $wgAutoloadAttemptLowercase is false.

    - (bug T70087) Fix Special:ActiveUsers page for
      installations using PostgreSQL.

    - (bug T76254) Fix deleting of pages with PostgreSQL.
      Requires a schema change and running update.php to
      fix.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1208072"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/155642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fca4ff1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"mediawiki-1.24.2-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}
