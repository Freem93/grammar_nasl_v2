#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1248. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24025);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:41:27 $");

  script_cve_id("CVE-2006-5876");
  script_osvdb_id(31667);
  script_xref(name:"DSA", value:"1248");

  script_name(english:"Debian DSA-1248-1 : libsoup - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Roland Lezuo and Josselin Mouette discovered that the libsoup HTTP
library performs insufficient sanitising when parsing HTTP headers,
which might lead to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=405197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1248"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libsoup package.

For the stable distribution (sarge) this problem has been fixed in
version 2.2.3-2sarge1.

For the upcoming stable distribution (etch) this problem has been
fixed in version 2.2.98-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/12");
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
if (deb_check(release:"3.1", prefix:"libsoup2.2-7", reference:"2.2.3-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libsoup2.2-dev", reference:"2.2.3-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libsoup2.2-doc", reference:"2.2.3-2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
