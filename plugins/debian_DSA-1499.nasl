#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1499. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31143);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/08/10 14:35:56 $");

  script_cve_id("CVE-2008-0674");
  script_osvdb_id(41989);
  script_xref(name:"DSA", value:"1499");

  script_name(english:"Debian DSA-1499-1 : pcre3 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that specially crafted regular expressions involving
codepoints greater than 255 could cause a buffer overflow in the PCRE
library (CVE-2008-0674 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1499"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pcre3 package.

For the old stable distribution (sarge), this problem has been fixed
in version 4.5+7.4-2.

For the stable distribution (etch), this problem has been fixed in
version 6.7+7.4-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pcre3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
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
if (deb_check(release:"3.1", prefix:"libpcre3", reference:"4.5+7.4-2")) flag++;
if (deb_check(release:"3.1", prefix:"libpcre3-dev", reference:"4.5+7.4-2")) flag++;
if (deb_check(release:"3.1", prefix:"pcregrep", reference:"4.5+7.4-2")) flag++;
if (deb_check(release:"3.1", prefix:"pgrep", reference:"4.5+7.4-2")) flag++;
if (deb_check(release:"4.0", prefix:"libpcre3", reference:"6.7+7.4-3")) flag++;
if (deb_check(release:"4.0", prefix:"libpcre3-dev", reference:"6.7+7.4-3")) flag++;
if (deb_check(release:"4.0", prefix:"libpcrecpp0", reference:"6.7+7.4-3")) flag++;
if (deb_check(release:"4.0", prefix:"pcregrep", reference:"6.7+7.4-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
