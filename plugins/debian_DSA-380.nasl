#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-380. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(15217);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2002-0164", "CVE-2003-0063", "CVE-2003-0071", "CVE-2003-0079", "CVE-2003-0730");
  script_bugtraq_id(4396, 6940, 6950, 8514);
  script_osvdb_id(4918, 60279, 60459);
  script_xref(name:"DSA", value:"380");

  script_name(english:"Debian DSA-380-1 : xfree86 - buffer overflows, denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"#use wml::fmt::verbatim

Four vulnerabilities have been discovered in XFree86.

  - CAN-2003-0063- xterm window title reporting escape
    sequence can deceive user
    The xterm package provides a terminal escape sequence
    that reports the window title by injecting it into the
    input buffer of the terminal window, as if the user had
    typed it. An attacker can craft an escape sequence that
    sets the title of a victim's xterm window to an
    arbitrary string (such as a shell command) and then
    reports that title. If the victim is at a shell prompt
    when this is done, the injected command will appear on
    the command line, ready to be run. Since it is not
    possible to embed a carriage return in the window title,
    the attacker would have to convince the victim to press
    Enter (or rely upon the victim's careless or confusion)
    for the shell or other interactive process to interpret
    the window title as user input. It is conceivable that
    the attacker could craft other escape sequences that
    might convince the victim to accept the injected input,
    however. The Common Vulnerabilities and Exposures
    project at cve.mitre.org has assigned the name
    CAN-2003-0063 to this issue.

  To determine whether your version of xterm is vulnerable to abuse of
  the window title reporting feature, run the following command at a
  shell prompt from within an xterm window :

    echo -e '\e[21t'

  (The terminal bell may ring, and the window title may be prefixed
  with an 'l'.)

  This flaw is exploitable by anything that can send output to a
  terminal window, such as a text document. The xterm user has to take
  action to cause the escape sequence to be sent, however (such as by
  viewing a malicious text document with the 'cat' command). Whether
  you are likely to be exposed to it depends on how you use xterm.
  Consider the following :

    echo -e '\e]2;s && echo rm -rf *\a' > /tmp/sploit echo -e '\e[21t'
    >> /tmp/sploit cat /tmp/sploit

  Debian has resolved this problem by disabling the window title
  reporting escape sequence in xterm; it is understood but ignored.
  The escape sequence to set the window title has not been disabled.

  A future release of the xterm package will have a configuration
  option to permit the user to turn the window title reporting feature
  back on, but it will default off.

  - CAN-2003-0071- xterm susceptible to DEC UDK escape
    sequence denial-of-service attack

    The xterm package, since it emulates DEC VT-series text
    terminals, emulates a feature of DEC VT terminals known
    as 'User-Defined Keys' (UDK for short). There is a bug
    in xterm's handling of DEC UDK escape sequences,
    however, and an ill-formed one can cause the xterm
    process to enter a tight loop. This causes the process
    to 'spin', consuming CPU cycles uselessly, and refusing
    to handle signals (such as efforts to kill the process
    or close the window).

  To determine whether your version of xterm is vulnerable to this
  attack, run the following command at a shell prompt from within a
  'sacrificial' xterm window (i.e., one that doesn't have anything in
  the scrollback buffer you might need to see later) :

    echo -e '\eP0;0|0A/17\x9c'

  This flaw is exploitable by anything that can send output to a
  terminal window, such as a text document. The xterm user has to take
  action to cause the escape sequence to be sent, however (such as by
  viewing a malicious text document with the 'cat' command). Whether
  you are likely to be exposed to it depends on how you use xterm.

  Debian has resolved this problem by backporting an upstream fix to
  XFree86 4.1.0.

  - CAN-2002-0164- flaw in X server's MIT-SHM extension
    permits user owning X session to read and write
    arbitrary shared memory segments

    Most X servers descended from the MIT/X Consortium/X.Org
    Sample Implementation, including XFree86's X servers,
    support an extension to the X protocol called MIT-SHM,
    which enables X clients running on the same host as the
    X server to operate more quickly and efficiently by
    taking advantage of an operating system feature called
    shared memory where it is available. The Linux kernel,
    for example, supports shared memory.

  Because the X server runs with elevated privileges, the operating
  system's built-in access control mechanisms are ineffective to
  police the X server's usage of segments of shared memory. The X
  server has to implement its own access control. This was imperfectly
  done in previous releases of XFree86 (and the MIT/X Consortium/X.Org
  Sample Implementation before it), leaving opportunities for
  malicious X clients to read and alter shared memory segments to
  which they should not have access. The Common Vulnerabilities and
  Exposures project at cve.mitre.org has assigned the name
  CAN-2002-0164 to this issue.

  Debian's XFree86 4.1.0-16 packages shipped with an incomplete fix
  for the this flaw, only enforcing proper access control for X
  servers that were not started by a display manager (e.g., xdm). This
  update resolves that problem.

  The Debian Project knows of no exploits for this vulnerability. A
  malicious X client that abused the MIT-SHM extension could
  conceivably be written however, and run (deliberately or
  unwittingly) by a user able to run an X server on a host. The impact
  of this flaw depends on how shared memory is used on the system. See
  the ipcs(8) manual page for more information.

  Debian has resolved this problem by backporting an upstream fix to
  XFree86 4.1.0.

  - CAN-2003-0730- multiple integer overflows in the font
    libraries for XFree86 allow local or remote attackers to
    cause a denial of service or execute arbitrary code via
    heap-based and stack-based buffer overflow attacks

    Security researcher 'blexim' wrote [paraphrased] :

    I have identified several bugs in the font libraries of the
    current version of the XFree86 source code. These bugs could
    potentially lead to the execution of arbitrary code by a remote
    user in any process which calls the functions in question. The
    functions are related to the transfer and enumeration of fonts
    from font servers to clients, limiting the range of the exposure
    caused by these bugs.

    Specifically, several sizing variables passed from a font server
    to a client are not adequately checked, causing calculations on
    them to result in erroneous values. These erroneous calculations
    can lead to buffers on the heap and stack overflowing, potentially
    leading to arbitrary code execution. As stated before, the risk is
    limited by the fact that only clients can be affected by these
    bugs, but in some (non-default) configurations, both xfs and the X
    server can act as clients to remote font servers. In these
    configurations, both xfs and the X server could be potentially
    compromised.

  The Common Vulnerabilities and Exposures project at cve.mitre.org
  has assigned the name CAN-2003-0730 to this issue.

  The Debian Project knows of no exploits for this vulnerability. By
  default in Debian, X servers are configured to listen only to a
  locally-running font server, which is not even used if the xfs
  package is not installed. The Debian default configuration of xfs
  uses only font directories on the local host, and does not attempt
  to connect to any external font servers.

  Debian has resolved this problem by backporting an upstream fix to
  XFree86 4.1.0.

All of the above problems also affect the xfree86v3 packages (in the
case of the first two flaws, the xterm source code contains the flaws,
but no xterm package is produced). Due to resource limitations and a
lack of upstream support for this legacy code, Debian is unable to
continue supporting version 3.3.6 of XFree86. To avoid exposure to the
latter two flaws in this advisory, we recommend that you remove the
following packages if you have them installed :

  - xserver-3dlabs
  - xserver-8514

  - xserver-agx

  - xserver-common-v3

  - xserver-fbdev

  - xserver-i128

  - xserver-mach32

  - xserver-mach64

  - xserver-mach8

  - xserver-mono

  - xserver-p9000

  - xserver-s3

  - xserver-s3v

  - xserver-svga

  - xserver-tga

  - xserver-vga16

  - xserver-w32

(You may also wish to remove the xext, xlib6, and xlib6-altdev
packages, as support for them is being terminated along with the rest
of the XFree86 3.3.6 packages, though they are not affected by the
flaws in this advisory.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-380"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) these problems have been fixed in
version 4.1.0-16woody1.

We recommend that you update your xfree86 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfree86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/06");
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
if (deb_check(release:"3.0", prefix:"lbxproxy", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libdps-dev", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libdps1", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libdps1-dbg", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6-dbg", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw6-dev", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7-dbg", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libxaw7-dev", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"proxymngr", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"twm", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"x-window-system", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"x-window-system-core", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xbase-clients", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xdm", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-100dpi", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-100dpi-transcoded", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-75dpi", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-75dpi-transcoded", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-base", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-base-transcoded", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-cyrillic", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-pex", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfonts-scalable", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfree86-common", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfs", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xfwp", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlib6g", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlib6g-dev", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa-dev", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa3", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibmesa3-dbg", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa-dev", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa3", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibosmesa3-dbg", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-dbg", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-dev", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xlibs-pic", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xmh", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xnest", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xprt", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xserver-common", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xserver-xfree86", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xspecs", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xterm", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xutils", reference:"4.1.0-16woody1")) flag++;
if (deb_check(release:"3.0", prefix:"xvfb", reference:"4.1.0-16woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
