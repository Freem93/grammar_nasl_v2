#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-210-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83164);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2013-0254", "CVE-2015-0295", "CVE-2015-1858", "CVE-2015-1859", "CVE-2015-1860");
  script_bugtraq_id(57772, 73029, 74302, 74307, 74309, 74310);
  script_osvdb_id(119072, 120574, 120575, 120576);

  script_name(english:"Debian DLA-210-1 : qt4-x11 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple security issues in the Qt library.

CVE-2013-0254

The QSharedMemory class uses weak permissions (world-readable and
world-writable) for shared memory segments, which allows local users
to read sensitive information or modify critical program data, as
demonstrated by reading a pixmap being sent to an X server.

CVE-2015-0295 / CVE-2015-1858 / CVE-2015-1859 / CVE-2015-1860

Denial of service (via segmentation faults) through crafted images
(BMP, GIF, ICO).

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/qt4-x11"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-multimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-opengl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-phonon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-scripttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-ibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-sqlite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-webkit-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-xmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-xmlpatterns-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-demos-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-qtconfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"libqt4-assistant", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-core", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-dbg", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-dbus", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-designer", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-dev", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-gui", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-help", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-multimedia", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-network", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-opengl", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-opengl-dev", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-phonon", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-qt3support", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-script", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-scripttools", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql-ibase", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql-mysql", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql-odbc", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql-psql", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql-sqlite", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql-sqlite2", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-sql-tds", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-svg", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-test", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-webkit", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-webkit-dbg", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-xml", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-xmlpatterns", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqt4-xmlpatterns-dbg", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqtcore4", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libqtgui4", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-demos", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-demos-dbg", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-designer", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-dev-tools", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-doc", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-doc-html", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-qmake", reference:"4:4.6.3-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"qt4-qtconfig", reference:"4:4.6.3-4+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
