#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2181. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52548);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-0715");
  script_osvdb_id(70964);
  script_xref(name:"DSA", value:"2181");

  script_name(english:"Debian DSA-2181-1 : subversion - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Philip Martin discovered that HTTP-based Subversion servers crash when
processing lock requests on repositories which support unauthenticated
read access."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2181"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.5.1dfsg1-6.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.12dfsg-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"subversion", reference:"1.5.1dfsg1-6")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-svn", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-dev", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-doc", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-java", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-perl", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby1.8", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn1", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"python-subversion", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"subversion", reference:"1.6.12dfsg-5")) flag++;
if (deb_check(release:"6.0", prefix:"subversion-tools", reference:"1.6.12dfsg-5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
