#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2599. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63384);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_xref(name:"DSA", value:"2599");

  script_name(english:"Debian DSA-2599-1 : nss - mis-issued intermediates");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google, Inc. discovered that the TurkTrust certification authority
included in the Network Security Service libraries (nss) mis-issued
two intermediate CAs which could be used to generate rogue end-entity
certificates. This update explicitly distrusts those two intermediate
CAs. The two existing TurkTrust root CAs remain active."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2599"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nss packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze6."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libnss3-1d", reference:"3.12.8-1+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libnss3-1d-dbg", reference:"3.12.8-1+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libnss3-dev", reference:"3.12.8-1+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libnss3-tools", reference:"3.12.8-1+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
