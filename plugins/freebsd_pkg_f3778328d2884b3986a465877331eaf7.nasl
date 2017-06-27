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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85370);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/09/23 13:29:16 $");

  script_cve_id("CVE-2015-3107", "CVE-2015-5124", "CVE-2015-5125", "CVE-2015-5127", "CVE-2015-5128", "CVE-2015-5129", "CVE-2015-5130", "CVE-2015-5131", "CVE-2015-5132", "CVE-2015-5133", "CVE-2015-5134", "CVE-2015-5539", "CVE-2015-5540", "CVE-2015-5541", "CVE-2015-5544", "CVE-2015-5545", "CVE-2015-5546", "CVE-2015-5547", "CVE-2015-5548", "CVE-2015-5549", "CVE-2015-5550", "CVE-2015-5551", "CVE-2015-5552", "CVE-2015-5553", "CVE-2015-5554", "CVE-2015-5555", "CVE-2015-5556", "CVE-2015-5557", "CVE-2015-5558", "CVE-2015-5559", "CVE-2015-5560", "CVE-2015-5561", "CVE-2015-5562", "CVE-2015-5563", "CVE-2015-5564");

  script_name(english:"FreeBSD : Adobe Flash Player -- critical vulnerabilities (f3778328-d288-4b39-86a4-65877331eaf7)");
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
"Adobe reports :

Adobe has released security updates for Adobe Flash Player. These
updates address critical vulnerabilities that could potentially allow
an attacker to take control of the affected system.

These updates resolve type confusion vulnerabilities that could lead
to code execution (CVE-2015-5128, CVE-2015-5554, CVE-2015-5555,
CVE-2015-5558, CVE-2015-5562).

These updates include further hardening to a mitigation introduced in
version 18.0.0.209 to defend against vector length corruptions
(CVE-2015-5125).

These updates resolve use-after-free vulnerabilities that could lead
to code execution (CVE-2015-5550, CVE-2015-5551, CVE-2015-3107,
CVE-2015-5556, CVE-2015-5130, CVE-2015-5134, CVE-2015-5539,
CVE-2015-5540, CVE-2015-5557, CVE-2015-5559, CVE-2015-5127,
CVE-2015-5563, CVE-2015-5561, CVE-2015-5124, CVE-2015-5564).

These updates resolve heap buffer overflow vulnerabilities that could
lead to code execution (CVE-2015-5129, CVE-2015-5541).

These updates resolve buffer overflow vulnerabilities that could lead
to code execution (CVE-2015-5131, CVE-2015-5132, CVE-2015-5133).

These updates resolve memory corruption vulnerabilities that could
lead to code execution (CVE-2015-5544, CVE-2015-5545, CVE-2015-5546,
CVE-2015-5547, CVE-2015-5548, CVE-2015-5549, CVE-2015-5552,
CVE-2015-5553).

These updates resolve an integer overflow vulnerability that could
lead to code execution (CVE-2015-5560)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb15-19.html"
  );
  # http://www.freebsd.org/ports/portaudit/f3778328-d288-4b39-86a4-65877331eaf7.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0a2294c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6_64-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-flashplugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
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

if (pkg_test(save_report:TRUE, pkg:"linux-c6-flashplugin<11.2r202.508")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6_64-flashplugin<11.2r202.508")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-flashplugin<11.2r202.508")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
