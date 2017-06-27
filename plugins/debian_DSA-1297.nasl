#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1297. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25301);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:41:27 $");

  script_cve_id("CVE-2007-0246");
  script_osvdb_id(36526);
  script_xref(name:"DSA", value:"1297");

  script_name(english:"Debian DSA-1297-1 : gforge-plugin-scmcvs - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bernhard R. Link discovered that the CVS browsing interface of Gforge,
a collaborative development tool, performs insufficient escaping of
URLs, which allows the execution of arbitrary shell commands with the
privileges of the www-data user.

The oldstable distribution (sarge) is not affected by this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1297"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gforge-plugin-scmcvs package.

For the stable distribution (etch) this problem has been fixed in
version 4.5.14-5etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gforge-plugin-scmcvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"gforge-plugin-scmcvs", reference:"4.5.14-5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
