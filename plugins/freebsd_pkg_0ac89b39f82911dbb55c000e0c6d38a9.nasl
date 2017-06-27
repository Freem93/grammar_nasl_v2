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
  script_id(25129);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-1322", "CVE-2007-1366", "CVE-2007-2893");

  script_name(english:"FreeBSD : qemu -- several vulnerabilities (0ac89b39-f829-11db-b55c-000e0c6d38a9)");
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
"The Debian Security Team reports :

Several vulnerabilities have been discovered in the QEMU processor
emulator, which may lead to the execution of arbitrary code or denial
of service. The Common Vulnerabilities and Exposures project
identifies the following problems :

CVE-2007-1320Tavis Ormandy discovered that a memory management routine
of the Cirrus video driver performs insufficient bounds checking,
which might allow the execution of arbitrary code through a heap
overflow.

CVE-2007-1321Tavis Ormandy discovered that the NE2000 network driver
and the socket code perform insufficient input validation, which might
allow the execution of arbitrary code through a heap overflow.

CVE-2007-1322Tavis Ormandy discovered that the 'icebp' instruction can
be abused to terminate the emulation, resulting in denial of service.

CVE-2007-1323Tavis Ormandy discovered that the NE2000 network driver
and the socket code perform insufficient input validation, which might
allow the execution of arbitrary code through a heap overflow.

CVE-2007-1366Tavis Ormandy discovered that the 'aam' instruction can
be abused to crash qemu through a division by zero, resulting in
denial of service."
  );
  # http://lists.debian.org/debian-security-announce/debian-security-announce-2007/msg00040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b656ca08"
  );
  # http://www.freebsd.org/ports/portaudit/0ac89b39-f829-11db-b55c-000e0c6d38a9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbea46f7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"qemu<0.9.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu>=0.9.0s.20070101*<0.9.0s.20070405_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel<0.9.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel>=0.9.0s.20070101*<0.9.0s.20070405_3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");