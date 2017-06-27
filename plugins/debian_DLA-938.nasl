#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-938-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100110);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2017-8386");
  script_osvdb_id(157331);

  script_name(english:"Debian DLA-938-1 : git security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Timo Schmid of ERNW GmbH discovered that the Git git-shell, a
restricted login shell for Git-only SSH access, allows a user to run
an interactive pager by causing it to spawn 'git upload-pack --help'.

For Debian 7 'Wheezy', these problems have been fixed in version
1:1.7.10.4-1+wheezy4.

We recommend that you upgrade your git packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/git"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"git", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-all", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-arch", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-core", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-cvs", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-daemon-run", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-daemon-sysvinit", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-doc", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-el", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-email", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-gui", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-man", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"git-svn", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"gitk", reference:"1:1.7.10.4-1+wheezy4")) flag++;
if (deb_check(release:"7.0", prefix:"gitweb", reference:"1:1.7.10.4-1+wheezy4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
