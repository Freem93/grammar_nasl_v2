#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2804. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71098);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6385", "CVE-2013-6386", "CVE-2013-6387", "CVE-2013-6388", "CVE-2013-6389");
  script_osvdb_id(100033, 100034, 100035, 100036, 100037);
  script_xref(name:"DSA", value:"2804");

  script_name(english:"Debian DSA-2804-1 : drupal7 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Drupal, a
fully-featured content management framework: Cross-site request
forgery, insecure pseudo random number generation, code execution,
incorrect security token validation and cross-site scripting.

In order to avoid the remote code execution vulnerability, it is
recommended to create a .htaccess file (or an equivalent configuration
directive in case you are not using Apache to serve your Drupal sites)
in each of your sites' 'files' directories (both public and private,
in case you have both configured).

Please refer to the NEWS file provided with this update and the
upstream advisory at drupal.org/SA-CORE-2013-003 for further
information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://drupal.org/SA-CORE-2013-003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/drupal7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2804"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the drupal7 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 7.14-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:drupal7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"drupal7", reference:"7.14-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
