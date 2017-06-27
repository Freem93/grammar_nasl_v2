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
  script_id(19013);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/08/09 10:50:39 $");

  script_cve_id("CVE-2004-1187", "CVE-2004-1188");

  script_name(english:"FreeBSD : mplayer -- multiple vulnerabilities (85d76f02-5380-11d9-a9e7-0001020eed82)");
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
"iDEFENSE and the MPlayer Team have found multiple vulnerabilities in
MPlayer :

- Potential heap overflow in Real RTSP streaming code

- Potential stack overflow in MMST streaming code

- Multiple buffer overflows in BMP demuxer

- Potential heap overflow in pnm streaming code

- Potential buffer overflow in mp3lib

These vulnerabilities could allow a remote attacker to execute
arbitrary code as the user running MPlayer. The problem in the pnm
streaming code also affects xine."
  );
  # http://mplayerhq.hu/homepage/design7/news.html#mplayer10pre5try2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0dfa981"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110322526210300
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110322526210300"
  );
  # http://www.idefense.com/application/poi/display?id=166
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c7dac8f"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110322829807443
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110322829807443"
  );
  # http://www.idefense.com/application/poi/display?id=167
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12ef3169"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110323022605345
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110323022605345"
  );
  # http://www.idefense.com/application/poi/display?id=168
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdbcba84"
  );
  # http://xinehq.de/index.php/security/XSA-2004-6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93d1630b"
  );
  # http://www.freebsd.org/ports/portaudit/85d76f02-5380-11d9-a9e7-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3fe0c80"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk2-esound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/21");
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

if (pkg_test(save_report:TRUE, pkg:"mplayer<0.99.5_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk<0.99.5_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk2<0.99.5_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-esound<0.99.5_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk-esound<0.99.5_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk2-esound<0.99.5_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxine<=1.0.r5_3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
