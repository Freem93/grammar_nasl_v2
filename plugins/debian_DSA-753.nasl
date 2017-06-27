#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-753. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18674);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1686");
  script_osvdb_id(16809);
  script_xref(name:"DSA", value:"753");

  script_name(english:"Debian DSA-753-1 : gedit - format string");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A format string vulnerability has been discovered in gedit, a
light-weight text editor for GNOME, that may allow attackers to cause
a denial of service (application crash) via a binary file with format
string specifiers in the filename. Since gedit supports opening files
via 'http://' URLs (through GNOME vfs) and other schemes, this might
be a remotely exploitable vulnerability.

The old stable distribution (woody) is not vulnerable to this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-753"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gedit package.

For the stable distribution (sarge) this problem has been fixed in
version 2.8.3-4sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gedit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/20");
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
if (deb_check(release:"3.1", prefix:"gedit", reference:"2.8.3-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gedit-common", reference:"2.8.3-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gedit-dev", reference:"2.8.3-4sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
