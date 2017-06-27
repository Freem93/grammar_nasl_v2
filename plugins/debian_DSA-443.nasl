#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-443. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15280);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2003-0690", "CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0093", "CVE-2004-0094", "CVE-2004-0106");
  script_bugtraq_id(9636, 9652, 9655, 9701);
  script_osvdb_id(6880, 6881);
  script_xref(name:"DSA", value:"443");

  script_name(english:"Debian DSA-443-1 : xfree86 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities have been discovered in XFree86. The
corrections are listed below with the identification from the Common
Vulnerabilities and Exposures (CVE) project :

  - CAN-2004-0083 :
    Buffer overflow in ReadFontAlias from dirfile.c of
    XFree86 4.1.0 through 4.3.0 allows local users and
    remote attackers to execute arbitrary code via a font
    alias file (font.alias) with a long token, a different
    vulnerability than CAN-2004-0084.

  - CAN-2004-0084 :

    Buffer overflow in the ReadFontAlias function in XFree86
    4.1.0 to 4.3.0, when using the CopyISOLatin1Lowered
    function, allows local or remote authenticated users to
    execute arbitrary code via a malformed entry in the font
    alias (font.alias) file, a different vulnerability than
    CAN-2004-0083.

  - CAN-2004-0106 :

    Miscellaneous additional flaws in XFree86's handling of
    font files.

  - CAN-2003-0690 :

    xdm does not verify whether the pam_setcred function
    call succeeds, which may allow attackers to gain root
    privileges by triggering error conditions within PAM
    modules, as demonstrated in certain configurations of
    the MIT pam_krb5 module.

  - CAN-2004-0093, CAN-2004-0094 :

    Denial-of-service attacks against the X server by
    clients using the GLX extension and Direct Rendering
    Infrastructure are possible due to unchecked client data
    (out-of-bounds array indexes [CAN-2004-0093] and integer
    signedness errors [CAN-2004-0094]).

Exploitation of CAN-2004-0083, CAN-2004-0084, CAN-2004-0106,
CAN-2004-0093 and CAN-2004-0094 would require a connection to the X
server. By default, display managers in Debian start the X server with
a configuration which only accepts local connections, but if the
configuration is changed to allow remote connections, or X servers are
started by other means, then these bugs could be exploited remotely.
Since the X server usually runs with root privileges, these bugs could
potentially be exploited to gain root privileges.

No attack vector for CAN-2003-0690 is known at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-443"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) these problems have been fixed in
version 4.1.0-16woody3.

We recommend that you update your xfree86 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfree86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"lbxproxy", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libdps-dev", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libdps1", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libdps1-dbg", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6-dbg", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6-dev", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7-dbg", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7-dev", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"proxymngr", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"twm", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"x-window-system", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"x-window-system-core", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xbase-clients", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xdm", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-100dpi", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-100dpi-transcoded", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-75dpi", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-75dpi-transcoded", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-base", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-base-transcoded", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-cyrillic", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-pex", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-scalable", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfree86-common", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfs", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xfwp", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlib6g", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlib6g-dev", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa-dev", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa3", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa3-dbg", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa-dev", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa3", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa3-dbg", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-dbg", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-dev", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-pic", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xmh", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xnest", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xprt", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xserver-common", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xserver-xfree86", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xspecs", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xterm", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xutils", reference:"4.1.0-16woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xvfb", reference:"4.1.0-16woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
