#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3303. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84598);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_bugtraq_id(75436, 75557);
  script_osvdb_id(123768, 124117);
  script_xref(name:"DSA", value:"3303");

  script_name(english:"Debian DSA-3303-1 : cups-filters - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the texttopdf utility, part of cups-filters,
was susceptible to multiple heap-based buffer overflows due to
improper handling of print jobs with a specially crafted line size.
This could allow remote attackers to crash texttopdf or possibly
execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/cups-filters"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/cups-filters"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3303"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups-filters packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.0.18-2.1+deb7u2.

For the stable distribution (jessie), these problems have been fixed
in version 1.0.61-5+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
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
if (deb_check(release:"7.0", prefix:"cups-filters", reference:"1.0.18-2.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsfilters-dev", reference:"1.0.18-2.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsfilters1", reference:"1.0.18-2.1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"cups-browsed", reference:"1.0.61-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-filters", reference:"1.0.61-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-filters-core-drivers", reference:"1.0.61-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsfilters-dev", reference:"1.0.61-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsfilters1", reference:"1.0.61-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfontembed-dev", reference:"1.0.61-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfontembed1", reference:"1.0.61-5+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
