#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2426. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58250);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:37:37 $");

  script_cve_id("CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543", "CVE-2011-1782", "CVE-2011-2896");
  script_bugtraq_id(45647, 48277, 49148);
  script_osvdb_id(70281, 70282, 70283, 70284, 74539);
  script_xref(name:"DSA", value:"2426");

  script_name(english:"Debian DSA-2426-1 : gimp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in GIMP, the GNU Image
Manipulation Program.

  - CVE-2010-4540
    Stack-based buffer overflow in the load_preset_response
    function in plug-ins/lighting/lighting-ui.c in the
    'LIGHTING EFFECTS & LIGHT' plugin allows user-assisted
    remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a long 'Position' field in a plugin configuration
    file.

  - CVE-2010-4541
    Stack-based buffer overflow in the loadit function in
    plug-ins/common/sphere-designer.c in the 'SPHERE
    DESIGNER' plugin allows user-assisted remote attackers
    to cause a denial of service (application crash) or
    possibly execute arbitrary code via a long 'Number of
    lights' field in a plugin configuration file.

  - CVE-2010-4542
    Stack-based buffer overflow in the
    gfig_read_parameter_gimp_rgb function in the GFIG plugin
    allows user-assisted remote attackers to cause a denial
    of service (application crash) or possibly execute
    arbitrary code via a long 'Foreground' field in a plugin
    configuration file.

  - CVE-2010-4543
    Heap-based buffer overflow in the read_channel_data
    function in file-psp.c in the Paint Shop Pro (PSP)
    plugin allows remote attackers to cause a denial of
    service (application crash) or possibly execute
    arbitrary code via a PSP_COMP_RLE (aka RLE compression)
    image file that begins a long run count at the end of
    the image.

  - CVE-2011-1782
    The correction for CVE-2010-4543 was incomplete.

  - CVE-2011-2896
    The LZW decompressor in the LZWReadByte function in
    plug-ins/common/file-gif-load.c does not properly handle
    code words that are absent from the decompression table
    when encountered, which allows remote attackers to
    trigger an infinite loop or a heap-based buffer
    overflow, and possibly execute arbitrary code, via a
    crafted compressed stream."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gimp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2426"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gimp packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.6.10-1+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"gimp", reference:"2.6.10-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"gimp-data", reference:"2.6.10-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"gimp-dbg", reference:"2.6.10-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgimp2.0", reference:"2.6.10-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgimp2.0-dev", reference:"2.6.10-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libgimp2.0-doc", reference:"2.6.10-1+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
