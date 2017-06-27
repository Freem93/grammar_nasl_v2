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
  script_id(82890);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/07/15 14:49:03 $");

  script_cve_id("CVE-2015-0346", "CVE-2015-0347", "CVE-2015-0348", "CVE-2015-0349", "CVE-2015-0350", "CVE-2015-0351", "CVE-2015-0352", "CVE-2015-0353", "CVE-2015-0354", "CVE-2015-0355", "CVE-2015-0356", "CVE-2015-0357", "CVE-2015-0358", "CVE-2015-0359", "CVE-2015-0360", "CVE-2015-3038", "CVE-2015-3039", "CVE-2015-3040", "CVE-2015-3041", "CVE-2015-3042", "CVE-2015-3043", "CVE-2015-3044");

  script_name(english:"FreeBSD : Adobe Flash Player -- critical vulnerabilities (3364d497-e4e6-11e4-a265-c485083ca99c)");
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
affected system. Adobe is aware of a report that an exploit for
CVE-2015-3043 exists in the wild, and recommends users update their
product installations to the latest versions.

- These updates resolve memory corruption vulnerabilities that could
lead to code execution (CVE-2015-0347, CVE-2015-0350, CVE-2015-0352,
CVE-2015-0353, CVE-2015-0354, CVE-2015-0355, CVE-2015-0360,
CVE-2015-3038, CVE-2015-3041, CVE-2015-3042, CVE-2015-3043).

- These updates resolve a type confusion vulnerability that could lead
to code execution (CVE-2015-0356).

- These updates resolve a buffer overflow vulnerability that could
lead to code execution (CVE-2015-0348).

- These updates resolve use-after-free vulnerabilities that could lead
to code execution (CVE-2015-0349, CVE-2015-0351, CVE-2015-0358,
CVE-2015-3039).

- These updates resolve double-free vulnerabilities that could lead to
code execution (CVE-2015-0346, CVE-2015-0359).

- These updates resolve memory leak vulnerabilities that could be used
to bypass ASLR (CVE-2015-0357, CVE-2015-3040).

- These updates resolve a security bypass vulnerability that could
lead to information disclosure (CVE-2015-3044)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb15-06.html"
  );
  # http://www.freebsd.org/ports/portaudit/3364d497-e4e6-11e4-a265-c485083ca99c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4917af08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-flashplugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");
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

if (pkg_test(save_report:TRUE, pkg:"linux-c6-flashplugin<=11.2r202.451")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-flashplugin<=11.2r202.451")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
