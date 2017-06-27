#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-4728dfe3ec.
#

include("compat.inc");

if (description)
{
  script_id(93139);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 16:52:28 $");

  script_cve_id("CVE-2016-4590", "CVE-2016-4591", "CVE-2016-4622", "CVE-2016-4624");
  script_xref(name:"FEDORA", value:"2016-4728dfe3ec");

  script_name(english:"Fedora 24 : webkitgtk4 (2016-4728dfe3ec)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update addresses the following vulnerabilities :

  -
    [CVE-2016-4622](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-4622),
    [CVE-2016-4624](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-4624),
    [CVE-2016-4591](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-4591),
    [CVE-2016-4590](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-4590)

Additional fixes :

  - Fix performance in accelerated compositing mode with the
    modesetting intel driver and DRI3 enabled.

  - Reduce the amount of file descriptors that the Web
    Process keeps open.

  - Fix Web Process deadlocks when loading HLS videos.

  - Make CSS and SVG animations run at 60fps.

  - Make meter elements accessible.

  - Improve accessibility name and description of elements
    to make it more compatible with W3C specs and fix
    several bugs in which the accessible name of objects was
    missing or broken.

  - Fix a crash when running windowed plugins under Wayland.

  - Fix a crash at process exit under Wayland.

  - Fix several crashes and rendering issues.

Translation updates :

  - German.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-4728dfe3ec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"webkitgtk4-2.12.4-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4");
}
