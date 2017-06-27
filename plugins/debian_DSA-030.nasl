#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-030. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(14867);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/06 20:12:49 $");

  script_bugtraq_id(1430, 2924, 2925);
  script_xref(name:"DSA", value:"030");

  script_name(english:"Debian DSA-030-2 : xfree86");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans, Joseph S. Myers, Michal Zalewski, Alan Cox, and others
have noted a number of problems in several components of the X Window
System sample implementation (from which XFree86 is derived). While
there are no known reports of real-world malicious exploits of any of
these problems, it is nevertheless suggested that you upgrade your
XFree86 packages immediately.

The scope of this advisory is XFree86 3.3.6 only, since that is the
version released with Debian GNU/Linux 2.2 ('potato'); Debian packages
of XFree86 4.0 and later have not been released as part of a Debian
distribution.

Several people are responsible for authoring the fixes to these
problems, including Aaron Campbell, Paulo Cesar Pereira de Andrade,
Keith Packard, David Dawes, Matthieu Herrb, Trevor Johnson, Colin
Phipps, and Branden Robinson.

  - The X servers are vulnerable to a denial-of-service
    attack during XC-SECURITY protocol negotiation.
  - X clients based on Xlib (which is most of them) are
    subject to potential buffer overflows in the _XReply()
    and _XAsyncReply() functions if they connect to a
    maliciously-coded X server that places bogus data in its
    X protocol replies. NOTE: This is only an effective
    attack against X clients running with elevated
    privileges (setuid or setgid programs), and offers
    potential access only to the elevated privilege. For
    instance, the most common setuid X client is probably
    xterm. On many Unix systems, xterm is setuid root; in
    Debian 2.2, xterm is only setgid utmp, which means that
    an effective exploit is limited to corruption of the
    lastlog, utmp, and wtmp files --not general root access.
    Also note that the attacker must already have sufficient
    privileges to start such an X client and successfully
    connect to the X server.

  - There is a buffer overflow (not stack-based) in xdm's
    XDMCP code.

  - There is a one-byte overflow in Xtrans.c.

  - Xtranssock.c is also subject to buffer overflow
    problems.

  - There is a buffer overflow with the -xkbmap X server
    flag.

  - The MultiSrc widget in the Athena widget library handle
    temporary files insecurely.

  - The imake program handles temporary files insecurely
    when executing install rules.

  - The ICE library is subject to buffer overflow attacks.

  - The xauth program handles temporary files insecurely.

  - The XauLock() function in the Xau library handles
    temporary files insecurely.

  - The gccmakedep and makedepend programs handle temporary
    files insecurely.

All of the above issues are resolved by this security release.


There are several other XFree86 security issues commonly discussed in
conjunction with the above, to which an up-to-date Debian 2.2 system
isNOT vulnerable :

  - There are 4 distinct problems with Xlib's XOpenDisplay()
    function in which a maliciously coded X server could
    cause a denial-of-service attack or buffer overflow. As
    before, this is only an effective attack against X
    clients running with elevated privileges, and the
    attacker must already have sufficient privileges to
    start such an X client and successfully connect to the X
    server. Debian 2.2 and 2.2r1 are only vulnerable to one
    of these problems, because we applied patches to XFree86
    3.3.6 to correct the other three. An additional patch
    applied for Debian 2.2r2 corrected the fourth.
  - The AsciiSrc widget in the Athena widget library handles
    temporary files insecurely. Debian 2.2r2 is not
    vulnerable to this problem because we applied a patch to
    correct it.

  - The imake program uses mktemp() instead of mkstemp().
    This problem does not exist in XFree86 3.3.6, and
    therefore no release of Debian 2.2 is affected.

These problems have been fixed in version 3.3.6-11potato32 and we
recommend that you upgrade your X packages immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-030"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected xfree86 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfree86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"rstart", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"rstartd", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"twm", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xbase", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xbase-clients", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xdm", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xext", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xf86setup", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xfree86-common", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xlib6g", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xlib6g-dev", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xlib6g-static", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xmh", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xnest", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xproxy", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xprt", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-3dlabs", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-common", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-fbdev", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-i128", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-mach64", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-mono", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-p9000", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-s3", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-s3v", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-svga", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-tga", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xserver-vga16", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xsm", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xterm", reference:"3.3.6-11potato32")) flag++;
if (deb_check(release:"2.2", prefix:"xvfb", reference:"3.3.6-11potato32")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
