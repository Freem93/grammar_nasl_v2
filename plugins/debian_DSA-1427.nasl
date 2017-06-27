#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1427. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29262);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-6015");
  script_osvdb_id(39191);
  script_xref(name:"DSA", value:"1427");

  script_name(english:"Debian DSA-1427-1 : samba - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alin Rad Pop discovered that Samba, a LanManager-like file and printer
server for Unix, is vulnerable to a buffer overflow in the nmbd code
which handles GETDC mailslot requests, which might lead to the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1427"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the old stable distribution (sarge), this problem has been fixed
in version 3.0.14a-3sarge11. Packages for m68k will be provided later.

For the stable distribution (etch), this problem has been fixed in
version 3.0.24-6etch9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/10");
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
if (deb_check(release:"3.1", prefix:"libpam-smbpass", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient-dev", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-samba", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"samba", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"samba-common", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"samba-dbg", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"samba-doc", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"smbclient", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"smbfs", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"swat", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"3.1", prefix:"winbind", reference:"3.0.14a-3sarge11")) flag++;
if (deb_check(release:"4.0", prefix:"libpam-smbpass", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient-dev", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"python-samba", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"samba", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"samba-common", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"samba-dbg", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc-pdf", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"smbclient", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"smbfs", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"swat", reference:"3.0.24-6etch9")) flag++;
if (deb_check(release:"4.0", prefix:"winbind", reference:"3.0.24-6etch9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
