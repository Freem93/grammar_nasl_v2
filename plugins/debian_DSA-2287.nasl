#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2287. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55721);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692");
  script_bugtraq_id(48474, 48618, 48660);
  script_osvdb_id(73493, 73982, 73983, 73984);
  script_xref(name:"DSA", value:"2287");

  script_name(english:"Debian DSA-2287-1 : libpng - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The PNG library libpng has been affected by several vulnerabilities.
The most critical one is the identified as CVE-2011-2690. Using this
vulnerability, an attacker is able to overwrite memory with an
arbitrary amount of data controlled by her via a crafted PNG image.

The other vulnerabilities are less critical and allow an attacker to
cause a crash in the program (denial of service) via a crafted PNG
image."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=632786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=633871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libpng"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2287"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.2.27-2+lenny5. Due to a technical limitation in the Debian
archive processing scripts, the updated packages cannot be released in
parallel with the packages for Squeeze. They will appear shortly.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.44-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpng", reference:"1.2.27-2+lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-0", reference:"1.2.44-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-0-udeb", reference:"1.2.44-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-dev", reference:"1.2.44-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpng3", reference:"1.2.44-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
