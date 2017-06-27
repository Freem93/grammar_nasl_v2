#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3838. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99741);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2016-10219", "CVE-2016-10220", "CVE-2017-5951", "CVE-2017-7207", "CVE-2017-8291");
  script_xref(name:"DSA", value:"3838");

  script_name(english:"Debian DSA-3838-1 : ghostscript - security update");
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
arbitrary code or denial of service if a specially crafted Postscript
file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=858350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=859666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=859694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=859696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=861295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ghostscript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3838"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ghostscript packages.

For the stable distribution (jessie), these problems have been fixed
in version 9.06~dfsg-2+deb8u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"ghostscript", reference:"9.06~dfsg-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-dbg", reference:"9.06~dfsg-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-doc", reference:"9.06~dfsg-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ghostscript-x", reference:"9.06~dfsg-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgs-dev", reference:"9.06~dfsg-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9", reference:"9.06~dfsg-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgs9-common", reference:"9.06~dfsg-2+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
