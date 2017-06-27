#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1422. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29257);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-5497");
  script_osvdb_id(40161);
  script_xref(name:"DSA", value:"1422");

  script_name(english:"Debian DSA-1422-1 : e2fsprogs - integer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Rafal Wojtczuk of McAfee AVERT Research discovered that e2fsprogs, the
ext2 file system utilities and libraries, contained multiple integer
overflows in memory allocations, based on sizes taken directly from
filesystem information. These could result in heap-based overflows
potentially allowing the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1422"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the e2fsprogs package.

For the stable distribution (etch), this problem has been fixed in
version 1.39+1.40-WIP-2006.11.14+dfsg-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
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
if (deb_check(release:"4.0", prefix:"comerr-dev", reference:"2.1-1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"e2fsck-static", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"e2fslibs", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"e2fslibs-dev", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"e2fsprogs", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libblkid-dev", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libblkid1", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libcomerr2", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libss2", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libuuid1", reference:"1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ss-dev", reference:"2.0-1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"uuid-dev", reference:"1.2-1.39+1.40-WIP-2006.11.14+dfsg-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
