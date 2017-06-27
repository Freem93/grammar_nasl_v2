#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1590. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32482);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2008-1105");
  script_xref(name:"DSA", value:"1590");

  script_name(english:"Debian DSA-1590-1 : samba - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alin Rad Pop discovered that Samba contained a buffer overflow
condition when processing certain responses received while acting as a
client, leading to arbitrary code execution (CVE-2008-1105 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=483410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1590"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (etch), this problem has been fixed in
version 3.0.24-6etch10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libpam-smbpass", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient-dev", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"python-samba", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"samba", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"samba-common", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"samba-dbg", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc-pdf", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"smbclient", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"smbfs", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"swat", reference:"3.0.24-6etch10")) flag++;
if (deb_check(release:"4.0", prefix:"winbind", reference:"3.0.24-6etch10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
