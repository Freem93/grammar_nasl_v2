#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-928. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22794);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-3341");
  script_osvdb_id(21934, 21935);
  script_xref(name:"DSA", value:"928");

  script_name(english:"Debian DSA-928-1 : dhis-tools-dns - insecure temporary file");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javier Fernandez-Sanguino Pena from the Debian Security Audit
project discovered that two scripts in the dhis-tools-dns package, DNS
configuration utilities for a dynamic host information System, which
are usually executed by root, create temporary files in an insecure
fashion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-928"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dhis-tools-dns package.

The old stable distribution (woody) does not contain a dhis-tools-dns
package.

For the stable distribution (sarge) these problems have been fixed in
version 5.0-3sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhis-tools-dns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"dhis-tools-dns", reference:"5.0-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"dhis-tools-genkeys", reference:"5.0-3sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");