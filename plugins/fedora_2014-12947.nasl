#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-12947.
#

include("compat.inc");

if (description)
{
  script_id(78798);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:44:46 $");

  script_cve_id("CVE-2014-1833");
  script_bugtraq_id(65260);
  script_xref(name:"FEDORA", value:"2014-12947");

  script_name(english:"Fedora 21 : devscripts-2.14.10-1.fc21 (2014-12947)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to version 2.14.10, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.14.10_changelog for details. Update to version 2.14.9, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.14.9_changelog for details. Update to version 2.14.8, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.14.8_changelog for details. Fixes CVE-2014-1833. Update to
version 2.14.9, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.14.9_changelog for details. Update to version 2.14.8, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.14.8_changelog for details. Fixes CVE-2014-1833.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/devscripts_2.14.10_changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3fee380"
  );
  # http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/devscripts_2.14.8_changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a740fad6"
  );
  # http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/devscripts_2.14.9_changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f84508fc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1059947"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/142006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b897cfdf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected devscripts package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC21", reference:"devscripts-2.14.10-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devscripts");
}
