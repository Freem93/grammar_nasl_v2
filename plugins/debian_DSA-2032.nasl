#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2032. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45480);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-2042", "CVE-2010-0205");
  script_bugtraq_id(35233, 38478);
  script_osvdb_id(54915, 62670);
  script_xref(name:"DSA", value:"2032");

  script_name(english:"Debian DSA-2032-1 : libpng - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in libpng, a library for
reading and writing PNG files. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2009-2042
    libpng does not properly parse 1-bit interlaced images
    with width values that are not divisible by 8, which
    causes libpng to include uninitialized bits in certain
    rows of a PNG file and might allow remote attackers to
    read portions of sensitive memory via 'out-of-bounds
    pixels' in the file.

  - CVE-2010-0205
    libpng does not properly handle compressed
    ancillary-chunk data that has a disproportionately large
    uncompressed representation, which allows remote
    attackers to cause a denial of service (memory and CPU
    consumption, and application hang) via a crafted PNG
    file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=533676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=572308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2032"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng package.

For the stable distribution (lenny), these problems have been fixed in
version 1.2.27-2+lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpng12-0", reference:"1.2.27-2+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libpng12-dev", reference:"1.2.27-2+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libpng3", reference:"1.2.27-2+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
