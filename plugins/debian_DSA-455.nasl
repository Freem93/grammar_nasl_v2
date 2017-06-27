#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-455. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15292);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2004-0110");
  script_bugtraq_id(9718);
  script_xref(name:"DSA", value:"455");

  script_name(english:"Debian DSA-455-1 : libxml - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libxml2 is a library for manipulating XML files.

Yuuichi Teranishi (Si Xi  Yu [?] ) discovered a flaw in libxml, the
GNOME XML library. When fetching a remote resource via FTP or HTTP,
the library uses special parsing routines which can overflow a buffer
if passed a very long URL. If an attacker is able to find an
application using libxml1 or libxml2 that parses remote resources and
allows the attacker to craft the URL, then this flaw could be used to
execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-455"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml1 and libxml2 packages.

For the stable distribution (woody) this problem has been fixed in
version 1.8.17-2woody1 of libxml and version 2.4.19-4woody1 of
libxml2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libxml-dev", reference:"1.8.17-2woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxml1", reference:"1.8.17-2woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxml2", reference:"2.4.19-4woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxml2-dev", reference:"2.4.19-4woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
