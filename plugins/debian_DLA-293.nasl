#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-293-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85419);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:17 $");

  script_cve_id("CVE-2015-3187");
  script_osvdb_id(125799);

  script_name(english:"Debian DLA-293-1 : subversion security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"C. Michael Pilato, from CollabNet, reported an issue in the version
control system Subversion.

CVE-2015-3187

Subversion servers revealed some sensible paths hidden by path-based
authorization. Remote authenticated users were allowed to obtain path
information by reading the history of a node that has been moved from
a hidden path. The vulnerability only revealed the path, though it
didn't reveal its content.

For Debian 6 'Squeeze', this issue has been fixed in
subversion 1.6.12dfsg-7+deb6u3. We recommend to upgrade your
subversion packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/08/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/subversion"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");
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
if (deb_check(release:"6.0", prefix:"libapache2-svn", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-dev", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-doc", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-java", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-perl", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby1.8", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn1", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"python-subversion", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"subversion", reference:"1.6.12dfsg-7+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"subversion-tools", reference:"1.6.12dfsg-7+deb6u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
