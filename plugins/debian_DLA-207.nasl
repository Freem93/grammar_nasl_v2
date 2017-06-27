#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-207-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83060);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849", "CVE-2014-0032", "CVE-2015-0248", "CVE-2015-0251");
  script_bugtraq_id(58323, 58895, 58896, 58897, 65434, 74259, 74260);
  script_osvdb_id(102927, 120099, 120121);

  script_name(english:"Debian DLA-207-1 : subversion security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Subversion, a version
control system. The Common Vulnerabilities and Exposures project
identifies the following problems :

CVE-2015-0248

Subversion mod_dav_svn and svnserve were vulnerable to a remotely
triggerable assertion DoS vulnerability for certain requests with
dynamically evaluated revision numbers.

CVE-2015-0251

Subversion HTTP servers allow spoofing svn:author property values for
new revisions via specially crafted v1 HTTP protocol request
sequences.

CVE-2013-1845

Subversion mod_dav_svn was vulnerable to a denial of service attack
through a remotely triggered memory exhaustion.

CVE-2013-1846 / CVE-2013-1847 / CVE-2013-1849 / CVE-2014-0032

Subversion mod_dav_svn was vulnerable to multiple remotely triggered
crashes.

This update has been prepared by James McCoy.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/subversion"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");
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
if (deb_check(release:"6.0", prefix:"libapache2-svn", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-dev", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-doc", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-java", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-perl", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby1.8", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn1", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"python-subversion", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"subversion", reference:"1.6.12dfsg-7+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"subversion-tools", reference:"1.6.12dfsg-7+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
