#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1417. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29191);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2007-6170");
  script_osvdb_id(38932);
  script_xref(name:"DSA", value:"1417");

  script_name(english:"Debian DSA-1417-1 : asterisk - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tilghman Lesher discovered that the logging engine of Asterisk, a free
software PBX and telephony toolkit, performs insufficient sanitising
of call-related data, which may lead to SQL injection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1417"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the old stable distribution (sarge), this problem has been fixed
in version 1:1.0.7.dfsg.1-2sarge6.

For the stable distribution (etch), this problem has been fixed in
version 1:1.2.13~dfsg-2etch2. Updated packages for ia64 will be
provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"asterisk", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-config", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-dev", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-doc", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-gtk-console", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-h323", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-sounds-main", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-web-vmail", reference:"1:1.0.7.dfsg.1-2sarge6")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-bristuff", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-classic", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-config", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-dev", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-doc", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-h323", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-sounds-main", reference:"1:1.2.13~dfsg-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-web-vmail", reference:"1:1.2.13~dfsg-2etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
