#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2019. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45113);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2010-0421");
  script_bugtraq_id(38760);
  script_osvdb_id(63090);
  script_xref(name:"DSA", value:"2019");

  script_name(english:"Debian DSA-2019-1 : pango1.0 - missing input sanitization");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marc Schoenefeld discovered an improper input sanitization in Pango, a
library for layout and rendering of text, leading to array indexing
error. If a local user was tricked into loading a specially crafted
font file in an application, using the Pango font rendering library,
it could lead to denial of service (application crash)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=574021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2019"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pango1.0 package.

For the stable distribution (lenny), this problem has been fixed in
version 1.20.5-5+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pango1.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpango1.0-0", reference:"1.20.5-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-0-dbg", reference:"1.20.5-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-common", reference:"1.20.5-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-dev", reference:"1.20.5-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-doc", reference:"1.20.5-5+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
