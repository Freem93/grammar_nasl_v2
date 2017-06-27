#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2428. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58295);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1136", "CVE-2012-1142", "CVE-2012-1144");
  script_bugtraq_id(52318);
  script_osvdb_id(79880, 79881, 79883, 79889, 79891);
  script_xref(name:"DSA", value:"2428");

  script_name(english:"Debian DSA-2428-1 : freetype - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mateusz Jurczyk from the Google Security Team discovered several
vulnerabilties in Freetype's parsing of BDF, Type1 and TrueType fonts,
which could result in the execution of arbitrary code if a malformed
font file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/freetype"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2428"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freetype packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.2-2.1+squeeze4. The updated packages are already available
since yesterday, but the advisory text couldn't be send earlier."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"freetype2-demos", reference:"2.4.2-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libfreetype6", reference:"2.4.2-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libfreetype6-dev", reference:"2.4.2-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libfreetype6-udeb", reference:"2.4.2-2.1+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
