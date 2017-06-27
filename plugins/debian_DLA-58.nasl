#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-58-3. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82204);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_name(english:"Debian DLA-58-3 : apt robustness improvements");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The recent security updates to apt make apt bug #710924 [1] much
easier to trigger. Affected users see '416 Requested Range Not
Satisfiable' errors during a apt-get update operation. With the
0.8.10.3+squeeze7 upload the fix for this error that was originally
introduced in version 0.9.12 [2] is now backported.

[1] https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=710924 [2]
http://anonscm.debian.org/cgit/apt/apt.git/commit/?id=331e8396ee5a4f2e
7d276eddc54749b2a13dd789

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # http://anonscm.debian.org/cgit/apt/apt.git/commit/?id=331e8396ee5a4f2e7d276eddc54749b2a13dd789
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?092a3efd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=710924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/10/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/apt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-transport-https");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"apt", reference:"0.8.10.3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apt-doc", reference:"0.8.10.3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apt-transport-https", reference:"0.8.10.3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apt-utils", reference:"0.8.10.3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libapt-pkg-dev", reference:"0.8.10.3+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libapt-pkg-doc", reference:"0.8.10.3+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
