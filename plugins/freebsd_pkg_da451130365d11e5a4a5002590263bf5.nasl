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
  script_id(85234);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/08/20 14:06:57 $");

  script_cve_id("CVE-2015-5154");

  script_name(english:"FreeBSD : qemu, xen-tools -- QEMU heap overflow flaw with certain ATAPI commands (da451130-365d-11e5-a4a5-002590263bf5)");
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
"The Xen Project reports :

A heap overflow flaw was found in the way QEMU's IDE subsystem handled
I/O buffer access while processing certain ATAPI commands.

A privileged guest user in a guest with CDROM drive enabled could
potentially use this flaw to execute arbitrary code on the host with
the privileges of the host's QEMU process corresponding to the guest."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xenbits.xen.org/xsa/advisory-138.html"
  );
  # http://git.qemu.org/?p=qemu.git;a=commit;h=e40db4c6d391419c0039fe274c74df32a6ca1a28
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?307c5e42"
  );
  # http://www.freebsd.org/ports/portaudit/da451130-365d-11e5-a4a5-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f6d8dba"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-sbruno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/05");
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

if (pkg_test(save_report:TRUE, pkg:"qemu<=0.11.1_20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu>=0.12<=2.3.0_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel<=0.11.1_20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel>=0.12<=2.3.0_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-sbruno<2.4.50.g20150814")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-user-static<2.4.50.g20150814")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xen-tools<4.5.0_9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
