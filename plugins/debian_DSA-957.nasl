#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-957. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22823);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/09 14:23:23 $");

  script_cve_id("CVE-2005-4601");
  script_bugtraq_id(16093);
  script_osvdb_id(22121);
  script_xref(name:"DSA", value:"957");

  script_name(english:"Debian DSA-957-2 : imagemagick - missing shell meta sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Weimer discovered that delegate code in ImageMagick is
vulnerable to shell command injection using specially crafted file
names. This allows attackers to encode commands inside of graphic
commands. With some user interaction, this is exploitable through Gnus
and Thunderbird. This update filters out the '$' character as well,
which was forgotten in the former update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=345238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-957"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the old stable distribution (woody) this problem has been fixed in
version 5.4.4.5-1woody8.

For the stable distribution (sarge) this problem has been fixed in
version 6.0.6.2-2.6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"imagemagick", reference:"5.4.4.5-1woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick++5", reference:"5.4.4.5-1woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick++5-dev", reference:"5.4.4.5-1woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick5", reference:"5.4.4.5-1woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libmagick5-dev", reference:"5.4.4.5-1woody8")) flag++;
if (deb_check(release:"3.0", prefix:"perlmagick", reference:"5.4.4.5-1woody8")) flag++;
if (deb_check(release:"3.1", prefix:"imagemagick", reference:"6.0.6.2-2.6")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick++6", reference:"6.0.6.2-2.6")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick++6-dev", reference:"6.0.6.2-2.6")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick6", reference:"6.0.6.2-2.6")) flag++;
if (deb_check(release:"3.1", prefix:"libmagick6-dev", reference:"6.0.6.2-2.6")) flag++;
if (deb_check(release:"3.1", prefix:"perlmagick", reference:"6.0.6.2-2.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
