#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2330. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56663);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_xref(name:"DSA", value:"2330");

  script_name(english:"Debian DSA-2330-1 : simplesamlphp - XML encryption weakness");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Issues were found in the handling of XML encryption in simpleSAMLphp,
an application for federated authentication. The following two issues
have been addressed :

It may be possible to use an SP as an oracle to decrypt encrypted
messages sent to that SP.

It may be possible to use the SP as a key oracle which can be used to
forge messages from that SP by issuing 300000-2000000 queries to the
SP. 

The oldstable distribution (lenny) does not contain simplesamlphp."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/simplesamlphp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2330"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the simplesamlphp packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.3-2."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:simplesamlphp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/28");
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
if (deb_check(release:"6.0", prefix:"simplesamlphp", reference:"1.6.3-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
