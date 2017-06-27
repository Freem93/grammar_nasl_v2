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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83510);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2015/10/23 04:39:30 $");

  script_cve_id("CVE-2015-3456");
  script_xref(name:"IAVA", value:"2015-A-0115");

  script_name(english:"FreeBSD : qemu, xen and VirtualBox OSE -- possible VM escape and code execution ('VENOM') (2780e442-fc59-11e4-b18b-6805ca1d3bb1) (Venom)");
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
"Jason Geffner, CrowdStrike Senior Security Researcher reports :

VENOM, CVE-2015-3456, is a security vulnerability in the virtual
floppy drive code used by many computer virtualization platforms. This
vulnerability may allow an attacker to escape from the confines of an
affected virtual machine (VM) guest and potentially obtain
code-execution access to the host. Absent mitigation, this VM escape
could open access to the host system and all other VMs running on that
host, potentially giving adversaries significant elevated access to
the host's local network and adjacent systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=200255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=200256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=200257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://venom.crowdstrike.com/"
  );
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2015-3456-2542656.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2bd5df81"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xenbits.xen.org/xsa/advisory-133.html"
  );
  # http://www.freebsd.org/ports/portaudit/2780e442-fc59-11e4-b18b-6805ca1d3bb1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?debcf6d6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-sbruno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (pkg_test(save_report:TRUE, pkg:"qemu<0.11.1_19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu>=0.12<2.3.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel<0.11.1_19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel>=0.12<2.3.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-sbruno<2.3.50.g20150501_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"virtualbox-ose<4.3.28")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xen-tools>=4.5.0<4.5.0_5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
