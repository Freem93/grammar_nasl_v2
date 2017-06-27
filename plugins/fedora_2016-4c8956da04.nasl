#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-4c8956da04.
#

include("compat.inc");

if (description)
{
  script_id(89536);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/04 16:10:32 $");

  script_xref(name:"FEDORA", value:"2016-4c8956da04");

  script_name(english:"Fedora 22 : wordpress-4.4.1-1.fc22 (2016-4c8956da04)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**WordPress 4.4.1 Security and Maintenance Release** WordPress
versions 4.4 and earlier are affected by a cross-site scripting
vulnerability that could allow a site to be compromised. This was
reported by Crtc4L. There were also several non-security bug fixes: *
Emoji support has been updated to include all of the latest emoji
characters, including the new diverse emoji!
&eth;&#159;&#145;&eth;&#159;&#145;&#140;&eth;&#159;&#145;&#143; * Some
sites with older versions of OpenSSL installed were unable to
communicate with other services provided through some plugins. * If a
post URL was ever re-used, the site could redirect to the wrong post.
WordPress 4.4.1 fixes 52 bugs from 4.4. For more information, see the
[release notes](https://codex.wordpress.org/Version_4.4.1) or consult
the [list of
changes](https://core.trac.wordpress.org/query?milestone=4.4.1).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://codex.wordpress.org/Version_4.4.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://core.trac.wordpress.org/query?milestone=4.4.1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-January/175616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56af2394"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC22", reference:"wordpress-4.4.1-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
