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
  script_id(66341);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/10/16 10:40:37 $");

  script_cve_id("CVE-2013-2028", "CVE-2013-2070");

  script_name(english:"FreeBSD : nginx -- multiple vulnerabilities (efaa4071-b700-11e2-b1b9-f0def16c5c1b)");
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
"The nginx project reports :

A stack-based buffer overflow might occur in a worker process process
while handling a specially crafted request, potentially resulting in
arbitrary code execution. [CVE-2013-2028]

A security problem related to CVE-2013-2028 was identified, affecting
some previous nginx versions if proxy_pass to untrusted upstream HTTP
servers is used.

The problem may lead to a denial of service or a disclosure of a
worker process memory on a specially crafted response from an upstream
proxied server. [CVE-2013-2070]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000114.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000112.html"
  );
  # http://www.freebsd.org/ports/portaudit/efaa4071-b700-11e2-b1b9-f0def16c5c1b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1e7c88f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nginx-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"nginx>=1.2.0,1<=1.2.8,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nginx>=1.3.0,1<1.4.1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nginx-devel>=1.1.4<=1.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nginx-devel>=1.3.0<1.5.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
