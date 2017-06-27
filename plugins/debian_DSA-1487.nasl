#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1487. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30226);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2007-2645", "CVE-2007-6351", "CVE-2007-6352");
  script_osvdb_id(42652, 42653);
  script_xref(name:"DSA", value:"1487");

  script_name(english:"Debian DSA-1487-1 : libexif - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the EXIF parsing code
of the libexif library, which can lead to denial of service or the
execution of arbitrary code if a user is tricked into opening a
malformed image. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-2645
    Victor Stinner discovered an integer overflow, which may
    result in denial of service or potentially the execution
    of arbitrary code.

  - CVE-2007-6351
    Meder Kydyraliev discovered an infinite loop, which may
    result in denial of service.

  - CVE-2007-6352
    Victor Stinner discovered an integer overflow, which may
    result in denial of service or potentially the execution
    of arbitrary code.

This update also fixes two potential NULL pointer deferences."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1487"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libexif packages.

For the old stable distribution (sarge), these problems have been
fixed in 0.6.9-6sarge2.

For the stable distribution (etch), these problems have been fixed in
version 0.6.13-5etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexif");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libexif-dev", reference:"0.6.9-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libexif10", reference:"0.6.9-6sarge2")) flag++;
if (deb_check(release:"4.0", prefix:"libexif-dev", reference:"0.6.13-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libexif12", reference:"0.6.13-5etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
