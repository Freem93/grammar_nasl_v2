#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-12908.
#

include("compat.inc");

if (description)
{
  script_id(69005);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 21:02:58 $");

  script_cve_id("CVE-2013-4116");
  script_bugtraq_id(61083);
  script_xref(name:"FEDORA", value:"2013-12908");

  script_name(english:"Fedora 19 : node-gyp-0.10.6-1.fc19 / nodejs-fstream-0.1.23-1.fc19 / nodejs-glob-3.2.3-1.fc19 / etc (2013-12908)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the latest version of npm, fixing several bugs including a
minor security bug.

For more information about recent changes in npm, see the changelog at
GitHub: https://github.com/isaacs/npm/commits/v1.3.3

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=983918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=984202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=985305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/isaacs/npm/commits/v1.3.3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4f49601"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?506c2c4d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112174.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59d2b81c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112175.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1e0b698"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112176.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c438c7da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112177.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d2c2f70"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bad27466"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07bb357d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7b418ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?282f23d3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:node-gyp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-fstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-graceful-fs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-lockfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-npm-registry-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-npmlog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-semver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-sha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"node-gyp-0.10.6-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-fstream-0.1.23-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-glob-3.2.3-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-graceful-fs-2.0.0-2.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-lockfile-0.4.0-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-npm-registry-client-0.2.27-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-npmlog-0.0.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-semver-2.0.10-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-sha-1.0.1-4.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"npm-1.3.3-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "node-gyp / nodejs-fstream / nodejs-glob / nodejs-graceful-fs / etc");
}
