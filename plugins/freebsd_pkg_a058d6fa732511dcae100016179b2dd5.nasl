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
  script_id(26938);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/13 14:37:09 $");

  script_cve_id("CVE-2007-5137");
  script_xref(name:"Secunia", value:"26942");

  script_name(english:"FreeBSD : tcl/tk -- buffer overflow in ReadImage function (a058d6fa-7325-11dc-ae10-0016179b2dd5)");
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
"A Buffer overflow in the ReadImage function in generic/tkImgGIF.c in
Tcl/Tk, allows remote attackers to execute arbitrary code via
multi-frame interlaced GIF files in which later frames are smaller
than the first."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/project/shownotes.php?release_id=541207"
  );
  # http://www.freebsd.org/ports/portaudit/a058d6fa-7325-11dc-ae10-0016179b2dd5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd2f3f78"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tk-threads");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"tk>8.2.*<8.2.3_11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tk>8.3.*<8.3.5_10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tk>8.4.*,2<8.4.16,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tk-threads>8.2.*<8.2.3_11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tk-threads>8.3.*<8.3.5_10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tk-threads>8.4.*,2<8.4.16,2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");