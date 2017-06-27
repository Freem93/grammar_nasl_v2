#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3245. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83231);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 18:23:49 $");

  script_cve_id("CVE-2015-1855");
  script_osvdb_id(120541);
  script_xref(name:"DSA", value:"3245");

  script_name(english:"Debian DSA-3245-1 : ruby1.8 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Ruby OpenSSL extension, part of the
interpreter for the Ruby language, did not properly implement hostname
matching, in violation of RFC 6125. This could allow remote attackers
to perform a man-in-the-middle attack via crafted SSL certificates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby1.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3245"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby1.8 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.8.7.358-7.1+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libruby1.8", reference:"1.8.7.358-7.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.8-dbg", reference:"1.8.7.358-7.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libtcltk-ruby1.8", reference:"1.8.7.358-7.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ri1.8", reference:"1.8.7.358-7.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8", reference:"1.8.7.358-7.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8-dev", reference:"1.8.7.358-7.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8-examples", reference:"1.8.7.358-7.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.8-full", reference:"1.8.7.358-7.1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
