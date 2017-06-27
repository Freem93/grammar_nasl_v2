#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2927. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73997);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/14 13:43:55 $");

  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_osvdb_id(106970, 106971, 106972, 106973, 106974, 106975, 106976, 106977, 106978, 106979, 106980, 106981);
  script_xref(name:"DSA", value:"2927");

  script_name(english:"Debian DSA-2927-1 : libxfont - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ilja van Sprundel of IOActive discovered several security issues in
the X.Org libXfont library, which may allow a local, authenticated
user to attempt to raise privileges; or a remote attacker who can
control the font server to attempt to execute code with the privileges
of the X server.

  - CVE-2014-0209
    Integer overflow of allocations in font metadata file
    parsing could allow a local user who is already
    authenticated to the X server to overwrite other memory
    in the heap.

  - CVE-2014-0210
    libxfont does not validate length fields when parsing
    xfs protocol replies allowing to write past the bounds
    of allocated memory when storing the returned data from
    the font server.

  - CVE-2014-0211
    Integer overflows calculating memory needs for xfs
    replies could result in allocating too little memory and
    then writing the returned data from the font server past
    the end of the allocated buffer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxfont"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libxfont"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2927"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxfont packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1:1.4.1-5.

For the stable distribution (wheezy), these problems have been fixed
in version 1:1.4.5-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxfont");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libxfont-dev", reference:"1:1.4.1-5")) flag++;
if (deb_check(release:"6.0", prefix:"libxfont1", reference:"1:1.4.1-5")) flag++;
if (deb_check(release:"6.0", prefix:"libxfont1-dbg", reference:"1:1.4.1-5")) flag++;
if (deb_check(release:"6.0", prefix:"libxfont1-udeb", reference:"1:1.4.1-5")) flag++;
if (deb_check(release:"7.0", prefix:"libxfont-dev", reference:"1:1.4.5-4")) flag++;
if (deb_check(release:"7.0", prefix:"libxfont1", reference:"1:1.4.5-4")) flag++;
if (deb_check(release:"7.0", prefix:"libxfont1-dbg", reference:"1:1.4.5-4")) flag++;
if (deb_check(release:"7.0", prefix:"libxfont1-udeb", reference:"1:1.4.5-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
