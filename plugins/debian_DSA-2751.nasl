#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2751. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69781);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4233", "CVE-2013-4234");
  script_bugtraq_id(61713, 61714);
  script_osvdb_id(96133, 96134, 104378);
  script_xref(name:"DSA", value:"2751");

  script_name(english:"Debian DSA-2751-1 : libmodplug - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in libmodplug, a library
for mod music based on ModPlug, that might allow arbitrary code
execution when processing specially crafted ABC files through
applications using the library, such as media players."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libmodplug"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libmodplug"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2751"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libmodplug packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1:0.8.8.1-1+squeeze2+git20130828.

For the stable distribution (wheezy), these problems have been fixed
in version 1:0.8.8.4-3+deb7u1+git20130828."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmodplug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/05");
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
if (deb_check(release:"6.0", prefix:"libmodplug-dev", reference:"1:0.8.8.1-1+squeeze2+git20130828")) flag++;
if (deb_check(release:"6.0", prefix:"libmodplug1", reference:"1:0.8.8.1-1+squeeze2+git20130828")) flag++;
if (deb_check(release:"7.0", prefix:"libmodplug-dev", reference:"1:0.8.8.4-3+deb7u1+git20130828")) flag++;
if (deb_check(release:"7.0", prefix:"libmodplug1", reference:"1:0.8.8.4-3+deb7u1+git20130828")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
