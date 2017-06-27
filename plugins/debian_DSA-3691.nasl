#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3691. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94023);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2013-5653", "CVE-2016-7976", "CVE-2016-7977", "CVE-2016-7978", "CVE-2016-7979", "CVE-2016-8602");
  script_osvdb_id(144952, 144999, 145000, 145250, 145251, 145549);
  script_xref(name:"DSA", value:"3691");

  script_name(english:"Debian DSA-3691-1 : ghostscript - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Ghostscript, the GPL
PostScript/PDF interpreter, which may lead to the execution of
arbitrary code or information disclosure if a specially crafted
Postscript file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=839118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=839260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=839841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=839845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=839846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=840451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ghostscript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3691"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ghostscript packages.

For the stable distribution (jessie), these problems have been fixed
in version 9.06~dfsg-2+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"ghostscript", reference:"9.06~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-dbg", reference:"9.06~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-doc", reference:"9.06~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-x", reference:"9.06~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libgs-dev", reference:"9.06~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9", reference:"9.06~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9-common", reference:"9.06~dfsg-2+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
