#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-306. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15143);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:07:15 $");

  script_cve_id("CVE-2003-0321", "CVE-2003-0322", "CVE-2003-0328");
  script_bugtraq_id(7096, 7097, 7099, 7100);
  script_xref(name:"DSA", value:"306");

  script_name(english:"Debian DSA-306-1 : ircii-pana - buffer overflows, integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Timo Sirainen discovered several problems in BitchX, a popular client
for Internet Relay Chat (IRC). A malicious server could craft special
reply strings, triggering the client to write beyond buffer boundaries
or allocate a negative amount of memory. This could lead to a denial
of service if the client only crashes, but may also lead to executing
of arbitrary code under the user id of the chatting user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-306"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the BitchX package.

For the stable distribution (woody) these problems have been fixed in
version 1.0-0c19-1.1.

For the old stable distribution (potato) these problems have been
fixed in version 1.0-0c16-2.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ircii-pana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"bitchx", reference:"1.0-0c16-2.1")) flag++;
if (deb_check(release:"2.2", prefix:"bitchx-gtk", reference:"1.0-0c16-2.1")) flag++;
if (deb_check(release:"3.0", prefix:"bitchx", reference:"1.0-0c19-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"bitchx-dev", reference:"1.0-0c19-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"bitchx-gtk", reference:"1.0-0c19-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"bitchx-ssl", reference:"1.0-0c19-1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
