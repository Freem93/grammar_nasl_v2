#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1303. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25465);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-1869", "CVE-2007-1870");
  script_osvdb_id(34175, 34176);
  script_xref(name:"DSA", value:"1303");

  script_name(english:"Debian DSA-1303-1 : lighttpd - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two problems were discovered with lighttpd, a fast webserver with
minimal memory footprint, which could allow denial of service. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-1869
    Remote attackers could cause denial of service by
    disconnecting partway through making a request.

  - CVE-2007-1870
    A NULL pointer dereference could cause a crash when
    serving files with a mtime of 0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=422254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1303"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd package.

For the stable distribution (etch) these problems have been fixed in
version 1.4.13-4etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");
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
if (deb_check(release:"4.0", prefix:"lighttpd", reference:"1.4.13-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-doc", reference:"1.4.13-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-cml", reference:"1.4.13-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-magnet", reference:"1.4.13-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.13-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.13-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-webdav", reference:"1.4.13-4etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
