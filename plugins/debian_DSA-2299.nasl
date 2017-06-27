#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2299. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56025);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_xref(name:"DSA", value:"2299");

  script_name(english:"Debian DSA-2299-1 : ca-certificates - compromised certificate authority");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An unauthorized SSL certificate has been found in the wild issued for
the DigiNotar Certificate Authority, obtained through a security
compromise with said company. Debian, like other software
distributors, has as a precaution decided to disable the DigiNotar
Root CA by default in its ca-certificates bundle.

For other software in Debian that ships a CA bundle, like the Mozilla
suite, updates are forthcoming."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=639744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/ca-certificates"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2299"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ca-certificates packages.

For the oldstable distribution (lenny), the ca-certificates package
does not contain this root CA.

For the stable distribution (squeeze), the root CA has been disabled
starting ca-certificates version 20090814+nmu3."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ca-certificates");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/01");
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
if (deb_check(release:"6.0", prefix:"ca-certificates", reference:"20090814+nmu3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
