#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1385. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26976);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-4568");
  script_osvdb_id(37721);
  script_xref(name:"DSA", value:"1385");

  script_name(english:"Debian DSA-1385-1 : xfs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sean Larsson discovered that two code paths inside the X Font Server
handle integer values insecurely, which may lead to the execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1385"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xfs packages.

For the oldstable distribution (sarge) this problem has been fixed in
version 4.3.0.dfsg.1-14sarge5 of xfree86. Packages for m68k are not
yet available. They will be provided later.

For the stable distribution (etch) this problem has been fixed in
version 1.0.1-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"lbxproxy", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libdps-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libdps1", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libdps1-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libice-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libice6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libice6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libsm-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libsm6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libsm6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libx11-6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libx11-6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libx11-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw6-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw7", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw7-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxaw7-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxext-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxext6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxext6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxft1", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxft1-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxi-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxi6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxi6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxmu-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxmu6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxmu6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxmuu-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxmuu1", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxmuu1-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxp-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxp6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxp6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxpm-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxpm4", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxpm4-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxrandr-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxrandr2", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxrandr2-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxt-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxt6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxt6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxtrap-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxtrap6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxtrap6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxtst-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxtst6", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxtst6-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxv-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxv1", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libxv1-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"pm-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"proxymngr", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"twm", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"x-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"x-window-system", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"x-window-system-core", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"x-window-system-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xbase-clients", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xdm", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-100dpi", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-100dpi-transcoded", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-75dpi", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-75dpi-transcoded", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-base", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-base-transcoded", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-cyrillic", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-scalable", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfree86-common", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfs", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xfwp", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-dri", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-dri-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-gl", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-gl-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-gl-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-glu", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-glu-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa-glu-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa3", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibmesa3-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibosmesa-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibosmesa4", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibosmesa4-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-data", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-pic", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-static-dev", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xlibs-static-pic", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xmh", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xnest", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xserver-common", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xserver-xfree86", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xserver-xfree86-dbg", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xspecs", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xterm", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xutils", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"xvfb", reference:"4.3.0.dfsg.1-14sarge5")) flag++;
if (deb_check(release:"4.0", prefix:"xfs", reference:"1.0.1-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
