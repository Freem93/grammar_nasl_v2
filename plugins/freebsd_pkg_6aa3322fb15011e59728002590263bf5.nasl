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
  script_id(87697);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/01/04 15:04:10 $");

  script_cve_id("CVE-2015-5278", "CVE-2015-5279");

  script_name(english:"FreeBSD : qemu -- denial of service vulnerabilities in NE2000 NIC support (6aa3322f-b150-11e5-9728-002590263bf5)");
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
"Prasad J Pandit, Red Hat Product Security Team, reports :

Qemu emulator built with the NE2000 NIC emulation support is
vulnerable to an infinite loop issue. It could occur when receiving
packets over the network.

A privileged user inside guest could use this flaw to crash the Qemu
instance resulting in DoS.

Qemu emulator built with the NE2000 NIC emulation support is
vulnerable to a heap buffer overflow issue. It could occur when
receiving packets over the network.

A privileged user inside guest could use this flaw to crash the Qemu
instance or potentially execute arbitrary code on the host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2015/09/15/2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2015/09/15/3"
  );
  # http://git.qemu.org/?p=qemu.git;a=commit;h=5a1ccdfe44946e726b4c6fda8a4493b3931a68c1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a73ba45"
  );
  # https://github.com/seanbruno/qemu-bsd-user/commit/737d2b3c41d59eb8f94ab7eb419b957938f24943
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3567ff21"
  );
  # http://git.qemu.org/?p=qemu.git;a=commit;h=7aa2bcad0ca837dd6d4bf4fa38a80314b4a6b755
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d6cd998"
  );
  # https://github.com/seanbruno/qemu-bsd-user/commit/9bbdbc66e5765068dce76e9269dce4547afd8ad4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?974ab7c8"
  );
  # http://www.freebsd.org/ports/portaudit/6aa3322f-b150-11e5-9728-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d497cfdc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-sbruno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"qemu<2.4.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel<2.4.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-sbruno<2.5.50.g20151224")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-user-static<2.5.50.g20151224")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
