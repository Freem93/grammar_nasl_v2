#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3231. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82930);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/18 14:49:02 $");

  script_cve_id("CVE-2015-0248", "CVE-2015-0251");
  script_osvdb_id(120099, 120121);
  script_xref(name:"DSA", value:"3231");

  script_name(english:"Debian DSA-3231-1 : subversion - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Subversion, a version
control system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2015-0248
    Subversion mod_dav_svn and svnserve were vulnerable to a
    remotely triggerable assertion DoS vulnerability for
    certain requests with dynamically evaluated revision
    numbers.

  - CVE-2015-0251
    Subversion HTTP servers allow spoofing svn:author
    property values for new revisions via specially crafted
    v1 HTTP protocol request sequences."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3231"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.6.17dfsg-4+deb7u9.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 1.8.10-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");
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
if (deb_check(release:"7.0", prefix:"libapache2-svn", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-dev", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-doc", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-java", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-perl", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby1.8", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn1", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"python-subversion", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"subversion", reference:"1.6.17dfsg-4+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"subversion-tools", reference:"1.6.17dfsg-4+deb7u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
