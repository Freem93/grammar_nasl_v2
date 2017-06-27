#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1285. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25152);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-1622", "CVE-2007-1893", "CVE-2007-1894", "CVE-2007-1897");
  script_xref(name:"DSA", value:"1285");

  script_name(english:"Debian DSA-1285-1 : wordpress - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- CVE-2007-1622
    Cross-site scripting (XSS) vulnerability in
    wp-admin/vars.php in WordPress before 2.0.10 RC2, and
    before 2.1.3 RC2 in the 2.1 series, allows remote
    authenticated users with theme privileges to inject
    arbitrary web script or HTML via the PATH_INFO in the
    administration interface, related to loose regular
    expression processing of PHP_SELF.

  - CVE-2007-1893
    WordPress 2.1.2, and probably earlier, allows remote
    authenticated users with the contributor role to bypass
    intended access restrictions and invoke the
    publish_posts functionality, which can be used
    to'publish a previously saved post.'

  - CVE-2007-1894
    Cross-site scripting (XSS) vulnerability in
    wp-includes/general-template.php in WordPress before
    20070309 allows remote attackers to inject arbitrary web
    script or HTML via the year parameter in the wp_title
    function.

  - CVE-2007-1897
    SQL injection vulnerability in xmlrpc.php in WordPress
    2.1.2, and probably earlier, allows remote authenticated
    users to execute arbitrary SQL commands via a string
    parameter value in an XML RPC mt.setPostCategories
    method call, related to the post_id variable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1285"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress package.

For the stable distribution (etch) these issues have been fixed in
version 2.0.10-1.

For the testing and unstable distributions (lenny and sid,
respectively), these issues have been fixed in version 2.1.3-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"wordpress", reference:"2.0.10-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
