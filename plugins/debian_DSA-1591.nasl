#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1591. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33077);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");
  script_bugtraq_id(29206);
  script_xref(name:"DSA", value:"1591");

  script_name(english:"Debian DSA-1591-1 : libvorbis - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local (remote) vulnerabilities have been discovered in
libvorbis, a library for the Vorbis general-purpose compressed audio
codec. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2008-1419
    libvorbis does not properly handle a zero value which
    allows remote attackers to cause a denial of service
    (crash or infinite loop) or trigger an integer overflow.

  - CVE-2008-1420
    Integer overflow in libvorbis allows remote attackers to
    execute arbitrary code via a crafted OGG file, which
    triggers a heap overflow.

  - CVE-2008-1423
    Integer overflow in libvorbis allows remote attackers to
    cause a denial of service (crash) or execute arbitrary
    code via a crafted OGG file which triggers a heap
    overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=482518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1591"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvorbis package.

For the stable distribution (etch), these problems have been fixed in
version 1.1.2.dfsg-1.4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libvorbis-dev", reference:"1.1.2.dfsg-1.4")) flag++;
if (deb_check(release:"4.0", prefix:"libvorbis0a", reference:"1.1.2.dfsg-1.4")) flag++;
if (deb_check(release:"4.0", prefix:"libvorbisenc2", reference:"1.1.2.dfsg-1.4")) flag++;
if (deb_check(release:"4.0", prefix:"libvorbisfile3", reference:"1.1.2.dfsg-1.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
