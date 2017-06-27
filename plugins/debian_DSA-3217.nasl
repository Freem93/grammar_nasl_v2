#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3217. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82670);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/15 13:45:11 $");

  script_cve_id("CVE-2015-0840");
  script_xref(name:"DSA", value:"3217");

  script_name(english:"Debian DSA-3217-1 : dpkg - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jann Horn discovered that the source package integrity verification in
dpkg-source can be bypassed via a specially crafted Debian source
control file (.dsc). Note that this flaw only affects extraction of
local Debian source packages via dpkg-source but not the installation
of packages from the Debian archive."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dpkg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3217"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dpkg packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.16.16. This update also includes non-security changes
previously scheduled for the next wheezy point release. See the Debian
changelog for details."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpkg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");
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
if (deb_check(release:"7.0", prefix:"dpkg", reference:"1.16.16")) flag++;
if (deb_check(release:"7.0", prefix:"dpkg-dev", reference:"1.16.16")) flag++;
if (deb_check(release:"7.0", prefix:"dselect", reference:"1.16.16")) flag++;
if (deb_check(release:"7.0", prefix:"libdpkg-dev", reference:"1.16.16")) flag++;
if (deb_check(release:"7.0", prefix:"libdpkg-perl", reference:"1.16.16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
