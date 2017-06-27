#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-0beb752b6e.
#

include("compat.inc");

if (description)
{
  script_id(97448);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/01 14:52:06 $");

  script_cve_id("CVE-2017-2350", "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2362", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365", "CVE-2017-2366", "CVE-2017-2369", "CVE-2017-2371", "CVE-2017-2373");
  script_xref(name:"FEDORA", value:"2017-0beb752b6e");

  script_name(english:"Fedora 25 : webkitgtk4 (2017-0beb752b6e)");
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
    [CVE-2017-2350](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2350),
    [CVE-2017-2354](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2354),
    [CVE-2017-2355](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2355),
    [CVE-2017-2356](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2356),
    [CVE-2017-2362](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2362),
    [CVE-2017-2363](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2363),
    [CVE-2017-2364](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2364),
    [CVE-2017-2365](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2365),
    [CVE-2017-2366](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2366),
    [CVE-2017-2369](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2369),
    [CVE-2017-2371](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2371),
    [CVE-2017-2373](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2017-2373)

Additional fixes :

  - Make accelerating compositing mode on-demand again. By
    default it will only be used for websites that require
    it, saving a lot of memory on websites that don&rsquo;t
    need it.

  - Release unused UpdateAtlas and reduce the tile coverage
    on memory pressure.

  - The media backend now stores preloaded media in /var/tmp
    instead of user cache dir.

  - Make inspector work again when accelerated compositing
    support is disabled.

  - Fix a deadlock when the media player is destroyed.

  - Fix network process crashes when loading custom URI
    schemes.

  - Fix overlay scrollbars that are over a subframe.

  - Fix a crash in GraphicsContext3D::drawArrays when using
    OpenGL 3.2 core profile.

  - Fix BadDamage X errors happening when resizing the
    WebView.

  - Fix several crashes and rendering issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-0beb752b6e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"webkitgtk4-2.14.5-1.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
