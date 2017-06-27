#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1496. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31056);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2008-0485", "CVE-2008-0486", "CVE-2008-0629", "CVE-2008-0630");
  script_osvdb_id(42197, 42199, 42200, 42201);
  script_xref(name:"DSA", value:"1496");

  script_name(english:"Debian DSA-1496-1 : mplayer - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several buffer overflows have been discovered in the MPlayer movie
player, which might lead to the execution of arbitrary code. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-0485
    Felipe Manzano and Anibal Sacco discovered a buffer
    overflow in the demuxer for MOV files.

  - CVE-2008-0486
    Reimar Doeffinger discovered a buffer overflow in the
    FLAC header parsing.

  - CVE-2008-0629
    Adam Bozanich discovered a buffer overflow in the CDDB
    access code.

  - CVE-2008-0630
    Adam Bozanich discovered a buffer overflow in URL
    parsing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1496"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mplayer packages.

The old stable distribution (sarge) doesn't contain mplayer.

For the stable distribution (etch), these problems have been fixed in
version 1.0~rc1-12etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
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
if (deb_check(release:"4.0", prefix:"mplayer", reference:"1.0~rc1-12etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mplayer-doc", reference:"1.0~rc1-12etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
