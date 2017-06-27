#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-095. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14932);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-1203");
  script_osvdb_id(2013);
  script_xref(name:"DSA", value:"095");

  script_name(english:"Debian DSA-095-1 : gpm - local root vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The package 'gpm' contains the gpm-root program, which can be used to
 create mouse-activated menus on the console. Among other problems,
 the gpm-root program contains a format string vulnerability, which
 allows an attacker to gain root privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-095"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in version 1.17.8-18.1, and we recommend that you
upgrade your 1.17.8-18 package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"gpm", reference:"1.17.8-18.1")) flag++;
if (deb_check(release:"2.2", prefix:"libgpm1", reference:"1.17.8-18.1")) flag++;
if (deb_check(release:"2.2", prefix:"libgpm1-altdev", reference:"1.17.8-18.1")) flag++;
if (deb_check(release:"2.2", prefix:"libgpmg1", reference:"1.17.8-18.1")) flag++;
if (deb_check(release:"2.2", prefix:"libgpmg1-dev", reference:"1.17.8-18.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
