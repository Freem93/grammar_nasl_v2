#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-2657.
#

include("compat.inc");

if (description)
{
  script_id(52692);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:05:53 $");

  script_cve_id("CVE-2011-0715");
  script_osvdb_id(70964);
  script_xref(name:"FEDORA", value:"2011-2657");

  script_name(english:"Fedora 14 : subversion-1.6.16-1.fc14 (2011-2657)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference flaw was found in the way the mod_dav_svn
module processed certain requests to lock working copy paths in a
repository. A remote attacker could issue a lock request that could
cause the httpd process serving the request to crash. (CVE-2011-0715)

The Fedora Project would like to thank Hyrum Wright of the Apache
Subversion project for reporting this issue. Upstream acknowledges
Philip Martin, WANdisco, Inc. as the original reporter.

Several bugs are also fixed in this update :

  - more improvement to the 'blame -g' memory leak from
    1.6.15

    - avoid unnecessary globbing for performance

    - don't add tree conflicts when one already exists

    - fix potential crash when requesting mergeinfo

    - don't attempt to resolve prop conflicts in 'merge
      --dry-run'

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=683198"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/056071.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc090d7b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/17");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"subversion-1.6.16-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
