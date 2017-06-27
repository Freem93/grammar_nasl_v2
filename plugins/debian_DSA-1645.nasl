#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1645. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34353);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");
  script_osvdb_id(48886, 48889);
  script_xref(name:"DSA", value:"1645");

  script_name(english:"Debian DSA-1645-1 : lighttpd - various");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local/remote vulnerabilities have been discovered in lighttpd,
a fast webserver with minimal memory footprint. 

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2008-4298
    A memory leak in the http_request_parse function could
    be used by remote attackers to cause lighttpd to consume
    memory, and cause a denial of service attack.

  - CVE-2008-4359
    Inconsistant handling of URL patterns could lead to the
    disclosure of resources a server administrator did not
    anticipate when using rewritten URLs.

  - CVE-2008-4360
    Upon filesystems which don't handle case-insensitive
    paths differently it might be possible that
    unanticipated resources could be made available by
    mod_userdir."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1645"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd package.

For the stable distribution (etch), these problems have been fixed in
version 1.4.13-4etch11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"lighttpd", reference:"1.4.13-4etch11")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-doc", reference:"1.4.13-4etch11")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-cml", reference:"1.4.13-4etch11")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-magnet", reference:"1.4.13-4etch11")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.13-4etch11")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.13-4etch11")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-webdav", reference:"1.4.13-4etch11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
