#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1294. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25259);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667");
  script_osvdb_id(34109, 34110, 34917, 34918);
  script_xref(name:"DSA", value:"1294");

  script_name(english:"Debian DSA-1294-1 : xfree86 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the X Window System,
which may lead to privilege escalation. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2007-1003
    Sean Larsson discovered an integer overflow in the
    XC-MISC extension, which might lead to denial of service
    or local privilege escalation.

  - CVE-2007-1351
    Greg MacManus discovered an integer overflow in the font
    handling, which might lead to denial of service or local
    privilege escalation.

  - CVE-2007-1352
    Greg MacManus discovered an integer overflow in the font
    handling, which might lead to denial of service or local
    privilege escalation.

  - CVE-2007-1667
    Sami Leides discovered an integer overflow in the libx11
    library which might lead to the execution of arbitrary
    code. This update introduces tighter sanity checking of
    input passed to XCreateImage(). To cope with this an
    updated rdesktop package is delivered along with this
    security update. Another application reported to break
    is the proprietary Opera browser, which isn't part of
    Debian. The vendor has released updated packages,
    though."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1294"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the XFree86 packages.

For the old stable distribution (sarge) these problems have been fixed
in version 4.3.0.dfsg.1-14sarge4. This update lacks builds for the
Sparc architecture, due to problems on the build host. Packages will
be released once this problem has been resolved.

The stable distribution (etch) isn't affected by these problems, as
the vulnerabilities have already been fixed during the Etch
preparation freeze phase."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfree86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"lbxproxy", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libdps-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libdps1", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libdps1-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libice-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libice6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libice6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libsm-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libsm6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libsm6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libx11-6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libx11-6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libx11-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw6-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw7", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw7-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw7-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxext-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxext6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxext6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxft1", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxft1-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxi-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxi6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxi6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxmu-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxmu6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxmu6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxmuu-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxmuu1", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxmuu1-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxp-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxp6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxp6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxpm-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxpm4", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxpm4-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxrandr-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxrandr2", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxrandr2-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxt-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxt6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxt6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxtrap-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxtrap6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxtrap6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxtst-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxtst6", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxtst6-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxv-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxv1", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libxv1-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pm-dev", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"proxymngr", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"rdesktop", reference:"1.4.0-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"twm", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"x-dev", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"x-window-system", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"x-window-system-core", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"x-window-system-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xbase-clients", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xdm", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-100dpi", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-100dpi-transcoded", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-75dpi", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-75dpi-transcoded", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-base", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-base-transcoded", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-cyrillic", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-scalable", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfree86-common", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xfs", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xfwp", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-dev", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-dri", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-dri-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-gl", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-gl-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-gl-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-glu", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-glu-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-glu-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa3", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa3-dbg", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xlibosmesa-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibosmesa4", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibosmesa4-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-data", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-dbg", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-dev", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-pic", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-static-dev", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-static-pic", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xmh", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xnest", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xserver-common", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xserver-xfree86", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xserver-xfree86-dbg", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xspecs", reference:"4.3.0.dfsg.1-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"xterm", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xutils", reference:"4.3.0.dfsg.1-14sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xvfb", reference:"4.3.0.dfsg.1-14sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
