#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-760. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19223);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1916");
  script_osvdb_id(17722, 18071, 18072);
  script_xref(name:"DSA", value:"760");

  script_name(english:"Debian DSA-760-1 : ekg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in ekg, a console Gadu
Gadu client, an instant messaging program. The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities :

  - CAN-2005-1850
    Marcin Owsiany and Wojtek Kaniewski discovered insecure
    temporary file creation in contributed scripts.

  - CAN-2005-1851

    Marcin Owsiany and Wojtek Kaniewski discovered potential
    shell command injection in a contributed script.

  - CAN-2005-1916

    Eric Romang discovered insecure temporary file creation
    and arbitrary command execution in a contributed script
    that can be exploited by a local attacker."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=317027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=318059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-760"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ekg package.

The old stable distribution (woody) does not contain an ekg package.

For the stable distribution (sarge) these problems have been fixed in
version 1.5+20050411-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ekg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"ekg", reference:"1.5+20050411-4")) flag++;
if (deb_check(release:"3.1", prefix:"libgadu-dev", reference:"1.5+20050411-4")) flag++;
if (deb_check(release:"3.1", prefix:"libgadu3", reference:"1.5+20050411-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
