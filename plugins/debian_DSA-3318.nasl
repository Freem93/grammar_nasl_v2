#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3318. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85032);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/06/15 16:38:32 $");

  script_cve_id("CVE-2015-1283");
  script_osvdb_id(122039);
  script_xref(name:"DSA", value:"3318");

  script_name(english:"Debian DSA-3318-1 : expat - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows have been discovered in Expat, an XML
parsing C library, which may result in denial of service or the
execution of arbitrary code if a malformed XML file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=793484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/expat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/expat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3318"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the expat packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 2.1.0-1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 2.1.0-6+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:expat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
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
if (deb_check(release:"7.0", prefix:"expat", reference:"2.1.0-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lib64expat1", reference:"2.1.0-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lib64expat1-dev", reference:"2.1.0-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libexpat1", reference:"2.1.0-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libexpat1-dev", reference:"2.1.0-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libexpat1-udeb", reference:"2.1.0-1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"expat", reference:"2.1.0-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64expat1", reference:"2.1.0-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64expat1-dev", reference:"2.1.0-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libexpat1", reference:"2.1.0-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libexpat1-dev", reference:"2.1.0-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libexpat1-udeb", reference:"2.1.0-6+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
