#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1301. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25503);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/03/19 14:28:18 $");

  script_cve_id("CVE-2007-2356");
  script_bugtraq_id(23680);
  script_xref(name:"DSA", value:"1301");

  script_name(english:"Debian DSA-1301-1 : gimp - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow has been identified in Gimp's SUNRAS plugin in
versions prior to 2.2.15. This bug could allow an attacker to execute
arbitrary code on the victim's computer by inducing the victim to open
a specially crafted RAS file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1301"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gimp package.

For the stable distribution (etch), this problem has been fixed in
version 2.2.13-1etch1.

For the old stable distribution (sarge), this problem has been fixed
in version 2.2.6-1sarge2.

For the unstable and testing distributions (sid and lenny,
respectively), this problem has been fixed in version 2.2.14-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
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
if (deb_check(release:"3.1", prefix:"gimp", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-data", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-helpbrowser", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-python", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"gimp-svg", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"gimp1.2", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgimp2.0", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgimp2.0-dev", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgimp2.0-doc", reference:"2.2.6-1sarge2")) flag++;
if (deb_check(release:"4.0", prefix:"gimp", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-data", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-dbg", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-helpbrowser", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-python", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gimp-svg", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgimp2.0", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgimp2.0-dev", reference:"2.2.13-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgimp2.0-doc", reference:"2.2.13-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
