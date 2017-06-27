#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-723. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18227);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-0605");
  script_bugtraq_id(12714);
  script_osvdb_id(14373);
  script_xref(name:"DSA", value:"723");

  script_name(english:"Debian DSA-723-1 : xfree86 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow has been discovered in the Xpm library which is used
in XFree86. A remote attacker could provide a specially crafted XPM
image that could lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=298939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-723"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xfree86 and associated packages.

For the stable distribution (woody) this problem has been fixed in
version 4.1.0-16woody6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfree86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"lbxproxy", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libdps-dev", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libdps1", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libdps1-dbg", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6-dbg", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6-dev", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7-dbg", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7-dev", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"proxymngr", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"twm", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"x-window-system", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"x-window-system-core", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xbase-clients", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xdm", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-100dpi", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-100dpi-transcoded", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-75dpi", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-75dpi-transcoded", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-base", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-base-transcoded", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-cyrillic", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-pex", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-scalable", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfree86-common", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfs", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xfwp", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlib6g", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlib6g-dev", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa-dev", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa3", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa3-dbg", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa-dev", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa3", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa3-dbg", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-dbg", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-dev", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-pic", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xmh", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xnest", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xprt", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xserver-common", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xserver-xfree86", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xspecs", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xterm", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xutils", reference:"4.1.0-16woody6")) flag++;
if (deb_check(release:"3.0", prefix:"xvfb", reference:"4.1.0-16woody6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
