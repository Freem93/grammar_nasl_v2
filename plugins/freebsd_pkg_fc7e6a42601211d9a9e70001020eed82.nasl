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
  script_id(19184);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/06/22 00:15:02 $");

  script_cve_id("CVE-2004-1308");
  script_bugtraq_id(12075);
  script_xref(name:"CERT", value:"125598");

  script_name(english:"FreeBSD : tiff -- directory entry count integer overflow vulnerability (fc7e6a42-6012-11d9-a9e7-0001020eed82)");
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
"In an iDEFENSE Security Advisory infamous41md reports :

Remote exploitation of a heap-based buffer overflow vulnerability
within the LibTIFF package could allow attackers to execute arbitrary
code.

The vulnerability specifically exists due to insufficient validation
of user-supplied data when calculating the size of a directory entry.
A TIFF file includes a number of directory entry header fields that
describe the data in the file. Included in these entries is an entry
count and offset value that are calculated to determine the size and
location of the data for that entry."
  );
  # http://www.idefense.com/application/poi/display?id=174&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4583297c"
  );
  # http://www.freebsd.org/ports/portaudit/fc7e6a42-6012-11d9-a9e7-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ff6b725"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fractorama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:iv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ivtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-iv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-libimg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:paraview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pdflib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pdflib-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/06");
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

if (pkg_test(save_report:TRUE, pkg:"tiff<3.7.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-tiff<3.6.1_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pdflib<6.0.1_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pdflib-perl<6.0.1_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gdal<1.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ivtools<1.2.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"paraview<2.4.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fractorama<1.6.7_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"iv>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-iv>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-libimg>0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
