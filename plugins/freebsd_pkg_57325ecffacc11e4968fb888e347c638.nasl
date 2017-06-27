#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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
  script_id(83512);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/01/11 15:46:18 $");

  script_cve_id("CVE-2015-3885");

  script_name(english:"FreeBSD : dcraw -- integer overflow condition (57325ecf-facc-11e4-968f-b888e347c638)");
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
"ocert reports :

The dcraw tool, as well as several other projects re-using its code,
suffers from an integer overflow condition which lead to a buffer
overflow.

The vulnerability concerns the 'len' variable, parsed without
validation from opened images, used in the ljpeg_start() function.

A maliciously crafted raw image file can be used to trigger the
vulnerability, causing a Denial of Service condition."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ocert.org/advisories/ocert-2015-006.html"
  );
  # https://github.com/rawstudio/rawstudio/commit/983bda1f0fa5fa86884381208274198a620f006e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7eab75a2"
  );
  # https://github.com/LibRaw/LibRaw/commit/4606c28f494a750892c5c1ac7903e62dd1c6fdb5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e71e136a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://sourceforge.net/p/netpbm/code/2512/"
  );
  # http://www.freebsd.org/ports/portaudit/57325ecf-facc-11e4-968f-b888e347c638.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?629601a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cinepaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:darktable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dcraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dcraw-m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exact-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:flphoto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:freeimage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kodi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:lightzone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opengtl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rawstudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ufraw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"cinepaint>=0.22.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"darktable<1.6.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dcraw>=7.00<9.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dcraw-m>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"exact-image<0.9.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"flphoto>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"freeimage>=3.13.0<3.16.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kodi<14.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libraw<0.16.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"lightzone<4.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"netpbm<10.35.96")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opengtl>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rawstudio<2.0_11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ufraw<0.21")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
