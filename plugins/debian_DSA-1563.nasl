#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1563. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32125);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2008-1897");
  script_bugtraq_id(28901);
  script_osvdb_id(44649);
  script_xref(name:"DSA", value:"1563");

  script_name(english:"Debian DSA-1563-1 : asterisk - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joel R. Voss discovered that the IAX2 module of Asterisk, a free
software PBX and telephony toolkit performs insufficient validation of
IAX2 protocol messages, which may lead to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1563"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the stable distribution (etch), this problem has been fixed in
version 1.2.13~dfsg-2etch4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"asterisk", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-bristuff", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-classic", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-config", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-dev", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-doc", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-h323", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-sounds-main", reference:"1.2.13~dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-web-vmail", reference:"1.2.13~dfsg-2etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
