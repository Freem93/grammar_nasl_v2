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
  script_id(84132);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2015/08/16 13:17:08 $");

  script_cve_id("CVE-2015-3096", "CVE-2015-3097", "CVE-2015-3098", "CVE-2015-3099", "CVE-2015-3100", "CVE-2015-3101", "CVE-2015-3102", "CVE-2015-3103", "CVE-2015-3104", "CVE-2015-3105", "CVE-2015-3106", "CVE-2015-3107", "CVE-2015-3108");

  script_name(english:"FreeBSD : Adobe Flash Player -- critical vulnerabilities (1e63db88-1050-11e5-a4df-c485083ca99c)");
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

Adobe has released security updates for Adobe Flash Player for
Windows, Macintosh and Linux. These updates address vulnerabilities
that could potentially allow an attacker to take control of the
affected system.

These updates resolve a vulnerability (CVE-2015-3096) that could be
exploited to bypass the fix for CVE-2014-5333.

These updates improve memory address randomization of the Flash heap
for the Window 7 64-bit platform (CVE-2015-3097).

These updates resolve vulnerabilities that could be exploited to
bypass the same-origin-policy and lead to information disclosure
(CVE-2015-3098, CVE-2015-3099, CVE-2015-3102).

These updates resolve a stack overflow vulnerability that could lead
to code execution (CVE-2015-3100).

These updates resolve a permission issue in the Flash broker for
Internet Explorer that could be exploited to perform privilege
escalation from low to medium integrity level (CVE-2015-3101).

These updates resolve an integer overflow vulnerability that could
lead to code execution (CVE-2015-3104).

These updates resolve a memory corruption vulnerability that could
lead to code execution (CVE-2015-3105).

These updates resolve use-after-free vulnerabilities that could lead
to code execution (CVE-2015-3103, CVE-2015-3106, CVE-2015-3107).

These updates resolve a memory leak vulnerability that could be used
to bypass ASLR (CVE-2015-3108)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb15-11.html"
  );
  # http://www.freebsd.org/ports/portaudit/1e63db88-1050-11e5-a4df-c485083ca99c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf26648e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Drawing Fill Shader Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-flashplugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");
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

if (pkg_test(save_report:TRUE, pkg:"linux-c6-flashplugin<11.2r202.466")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-flashplugin<11.2r202.466")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
