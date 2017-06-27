#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2546. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62049);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-3547");
  script_bugtraq_id(55483);
  script_osvdb_id(85325);
  script_xref(name:"DSA", value:"2546");

  script_name(english:"Debian DSA-2546-1 : freeradius - stack-based buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Timo Warns discovered that the EAP-TLS handling of FreeRADIUS, a
high-performance and highly configurable RADIUS server, is not
properly performing length checks on user-supplied input before
copying to a local stack buffer. As a result, an unauthenticated
attacker can exploit this flaw to crash the daemon or execute
arbitrary code via crafted certificates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=687175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/freeradius"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2546"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freeradius packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.1.10+dfsg-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"freeradius", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-common", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-dbg", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-dialupadmin", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-iodbc", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-krb5", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-ldap", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-mysql", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-postgresql", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"freeradius-utils", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libfreeradius-dev", reference:"2.1.10+dfsg-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libfreeradius2", reference:"2.1.10+dfsg-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
