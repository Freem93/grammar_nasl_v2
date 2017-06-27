#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-15983.
#

include("compat.inc");

if (description)
{
  script_id(86166);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/18 16:42:52 $");

  script_cve_id("CVE-2015-5714", "CVE-2015-5715");
  script_xref(name:"FEDORA", value:"2015-15983");

  script_name(english:"Fedora 23 : wordpress-4.3.1-1.fc23 (2015-15983)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**WordPress 4.3.1 Security and Maintenance Release** [Upstream
announcement](https://wordpress.org/news/2015/09/wordpress-4-3-1/):
WordPress 4.3.1 is now available. This is a security release for all
previous versions and we strongly encourage you to update your sites
immediately. This release addresses three issues, including two
cross-site scripting vulnerabilities and a potential privilege
escalation. * WordPress versions 4.3 and earlier are vulnerable to a
cross-site scripting vulnerability when processing shortcode tags
(CVE-2015-5714). Reported by Shahar Tal and Netanel Rubin of Check
Point. * A separate cross-site scripting vulnerability was found in
the user list table. Reported by Ben Bidner of the WordPress security
team. * Finally, in certain cases, users without proper permissions
could publish private posts and make them sticky (CVE-2015-5715).
Reported by Shahar Tal and Netanel Rubin of Check Point. WordPress
4.3.1 also fixes twenty-six bugs. For more information, see the
[release notes](https://codex.wordpress.org/Version_4.3.1) or consult
the [list of
changes](https://core.trac.wordpress.org/log/branches/4.3/?rev=34199&s
t op_rev=33647).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1263657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://codex.wordpress.org/Version_4.3.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://core.trac.wordpress.org/log/branches/4.3/?rev=34199&st"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-September/167674.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65dad2b0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wordpress.org/news/2015/09/wordpress-4-3-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"wordpress-4.3.1-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
