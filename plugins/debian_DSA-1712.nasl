#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1712. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35547);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/17 23:49:55 $");

  script_cve_id("CVE-2009-0282");
  script_osvdb_id(53551);
  script_xref(name:"DSA", value:"1712");

  script_name(english:"Debian DSA-1712-1 : rt2400 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that an integer overflow in the 'Probe Request'
packet parser of the Ralinktech wireless drivers might lead to remote
denial of service or the execution of arbitrary code.

Please note that you need to rebuild your driver from the source
package in order to set this update into effect. Detailed instructions
can be found in /usr/share/doc/rt2400-source/README.Debian"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1712"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rt2400 package.

For the stable distribution (etch), this problem has been fixed in
version 1.2.2+cvs20060620-4+etch1.

For the upcoming stable distribution (lenny) and the unstable
distribution (sid), this problem has been fixed in version
1.2.2+cvs20080623-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt2400");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"rt2400", reference:"1.2.2+cvs20060620-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rt2400-source", reference:"1.2.2+cvs20060620-4+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
