#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(80923);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/23 14:31:03 $");

  script_cve_id("CVE-2012-6129");

  script_name(english:"FreeBSD : libutp -- remote denial of service or arbitrary code execution (0523fb7e-8444-4e86-812d-8de05f6f0dce)");
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
"NVD reports :

Stack-based buffer overflow in utp.cpp in libutp, as used in
Transmission before 2.74 and possibly other products, allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via crafted 'micro transport protocol packets.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/bittorrent/libutp/issues/38"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://trac.transmissionbt.com/ticket/5002"
  );
  # http://www.freebsd.org/ports/portaudit/0523fb7e-8444-4e86-812d-8de05f6f0dce.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb4be8e5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bittorrent-libutp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:transmission-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:transmission-deamon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:transmission-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:transmission-qt4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bittorrent-libutp<0.20130514_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"transmission-cli<2.74")) flag++;
if (pkg_test(save_report:TRUE, pkg:"transmission-deamon<2.74")) flag++;
if (pkg_test(save_report:TRUE, pkg:"transmission-gtk<2.74")) flag++;
if (pkg_test(save_report:TRUE, pkg:"transmission-qt4<2.74")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
