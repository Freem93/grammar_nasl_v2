#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(19031);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/08/09 10:50:39 $");

  script_cve_id("CVE-2005-1195");
  script_bugtraq_id(13270, 13271);

  script_name(english:"FreeBSD : mplayer & libxine -- MMS and Real RTSP buffer overflow vulnerabilities (91c606fc-b5d0-11d9-a788-0001020eed82)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A xine security announcement reports :

By a user receiving data from a malicious network streaming server, an
attacker can overrun a heap buffer, which can, on some systems, lead
to or help in executing attacker-chosen malicious code with the
permissions of the user running a xine-lib based media application.

Both the MMS and Real RTSP streaming client code made some too-strong
assumptions on the transferred data. Several critical bounds checks
were missing, resulting in the possibility of heap overflows, should
the remote server not adhere to these assumptions. In the MMS case, a
remote server could present content with too many individual streams;
in the RTSP case, a remote server's reply could have too many lines.

An attacker can set up a server delivering malicious data to the
users. This can be used to overflow a heap buffer, which can, with
certain implementations of heap management, lead to attacker chosen
data written to the stack. This can cause attacker-chosen code being
executed with the permissions of the user running the application. By
tricking users to retrieve a stream, which can be as easy as providing
a link on a website, this vulnerability can be exploited remotely."
  );
  # http://www.mplayerhq.hu/homepage/design7/news.html#vuln10
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b32edb6d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mplayerhq.hu/homepage/design7/news.html#vuln11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xinehq.de/index.php/security/XSA-2004-8"
  );
  # http://www.freebsd.org/ports/portaudit/91c606fc-b5d0-11d9-a788-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8fdfd86"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk2-esound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"mplayer<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk2<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-esound<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk-esound<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk2-esound<0.99.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxine>=0.9.9<1.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
