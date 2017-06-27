#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2199. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52946);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_xref(name:"DSA", value:"2199");

  script_name(english:"Debian DSA-2199-1 : iceape - ssl certificate blacklist update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for the Iceape internet suite, an unbranded version of
SeaMonkey, updates the certificate blacklist for several fraudulent
HTTPS certificates.

More details can be found in a blog posting by Jacob Appelbaum of the
Tor project.

The oldstable distribution (lenny) is not affected. The iceape package
only provides the XPCOM code."
  );
  # https://blog.torproject.org/category/tags/ssl-tls-ca-tor-certificates-torbrowser
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0859166b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/iceape"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2199"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-4."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"iceape", reference:"2.0.11-4")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-browser", reference:"2.0.11-4")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-chatzilla", reference:"2.0.11-4")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dbg", reference:"2.0.11-4")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dev", reference:"2.0.11-4")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-mailnews", reference:"2.0.11-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
