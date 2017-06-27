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
  script_id(18873);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/11/06 11:43:41 $");

  script_cve_id("CVE-2004-0994");

  script_name(english:"FreeBSD : zgv -- exploitable heap overflows (249a8c42-6973-11d9-ae49-000c41e2cdad)");
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
"infamous41md reports :

zgv uses malloc() frequently to allocate memory for storing image
data. When calculating how much to allocate, user-supplied data from
image headers is multiplied and/or added without any checks for
arithmetic overflows. We can overflow numerous calculations, and cause
small buffers to be allocated. Then we can overflow the buffer, and
eventually execute code. There are a total of 11 overflows that are
exploitable to execute arbitrary code.

These bugs exist in both zgv and xzgv."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=109886210702781
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=109886210702781"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=109898111915661
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=109898111915661"
  );
  # http://rus.members.beeb.net/xzgv.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff8096ed"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.svgalib.org/rus/zgv/"
  );
  # http://www.idefense.com/application/poi/display?id=160&type=vulnerabilities&flashstatus=false
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?344a1818"
  );
  # http://www.freebsd.org/ports/portaudit/249a8c42-6973-11d9-ae49-000c41e2cdad.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97583504"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xzgv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zgv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/18");
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

if (pkg_test(save_report:TRUE, pkg:"zgv<5.8_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xzgv<0.8_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
