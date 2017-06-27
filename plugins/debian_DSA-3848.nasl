#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3848. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100111);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2017-8386");
  script_osvdb_id(157331);
  script_xref(name:"DSA", value:"3848");

  script_name(english:"Debian DSA-3848-1 : git - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Timo Schmid of ERNW GmbH discovered that the Git git-shell, a
restricted login shell for Git-only SSH access, allows a user to run
an interactive pager by causing it to spawn 'git upload-pack --help'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3848"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the git packages.

For the stable distribution (jessie), this problem has been fixed in
version 1:2.1.4-2.1+deb8u3."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

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
if (deb_check(release:"8.0", prefix:"git", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-all", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-arch", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-core", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-cvs", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-run", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-daemon-sysvinit", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-doc", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-el", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-email", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-gui", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-man", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-mediawiki", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"git-svn", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"gitk", reference:"1:2.1.4-2.1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"gitweb", reference:"1:2.1.4-2.1+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
