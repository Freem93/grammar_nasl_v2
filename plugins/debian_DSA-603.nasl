#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-603. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15893);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-0975");
  script_osvdb_id(11125);
  script_xref(name:"DSA", value:"603");

  script_name(english:"Debian DSA-603-1 : openssl - insecure temporary file");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Trustix developers discovered insecure temporary file creation in a
supplemental script (der_chop) of the openssl package which may allow
local users to overwrite files via a symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-603"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl package.

For the stable distribution (woody) this problem has been fixed in
version 0.9.6c-2.woody.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/30");
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
if (deb_check(release:"3.0", prefix:"libssl-dev", reference:"0.9.6c-2.woody.7")) flag++;
if (deb_check(release:"3.0", prefix:"libssl0.9.6", reference:"0.9.6c-2.woody.7")) flag++;
if (deb_check(release:"3.0", prefix:"openssl", reference:"0.9.6c-2.woody.7")) flag++;
if (deb_check(release:"3.0", prefix:"ssleay", reference:"0.9.6c-2.woody.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
