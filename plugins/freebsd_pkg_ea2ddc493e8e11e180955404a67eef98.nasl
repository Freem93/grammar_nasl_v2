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
  script_id(57553);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/12/10 14:09:54 $");

  script_cve_id("CVE-2011-4351", "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2011-4579");

  script_name(english:"FreeBSD : ffmpeg -- multiple vulnerabilities (ea2ddc49-3e8e-11e1-8095-5404a67eef98)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ubuntu Security Notice USN-1320-1 reports :

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed QDM2 streams. If a user were tricked into opening a crafted
QDM2 stream file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2011-4351)

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed VP3 streams. If a user were tricked into opening a crafted
file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2011-4352)

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed VP5 and VP6 streams. If a user were tricked into opening a
crafted file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2011-4353)

It was discovered that FFmpeg incorrectly handled certain malformed
VMD files. If a user were tricked into opening a crafted VMD file, an
attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2011-4364)

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed SVQ1 streams. If a user were tricked into opening a crafted
SVQ1 stream file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2011-4579)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ubuntu.com/usn/usn-1320-1"
  );
  # http://www.freebsd.org/ports/portaudit/ea2ddc49-3e8e-11e1-8095-5404a67eef98.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d3dcb1a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"ffmpeg<0.7.11,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
