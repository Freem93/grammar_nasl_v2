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
  script_id(77836);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/12/03 05:39:37 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"FreeBSD : bash -- remote code execution vulnerability (71ad81da-4414-11e4-a33e-3c970e169bc2) (Shellshock)");
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
"Chet Ramey reports :

Under certain circumstances, bash will execute user code while
processing the environment for exported function definitions.

The original fix released for CVE-2014-6271 was not adequate. A
similar vulnerability was discovered and tagged as CVE-2014-7169."
  );
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dacf7829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.gnu.org/archive/html/bug-bash/2014-09/msg00081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2014/q3/690"
  );
  # http://www.freebsd.org/ports/portaudit/71ad81da-4414-11e4-a33e-3c970e169bc2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cdefdef"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bash-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux_base-c6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bash>3.0<=3.0.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash>3.1<=3.1.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash>3.2<=3.2.52")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash>4.0<=4.0.39")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash>4.1<=4.1.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash>4.2<=4.2.48")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash>4.3<4.3.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash-static>3.0<=3.0.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash-static>3.1<=3.1.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash-static>3.2<=3.2.52")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash-static>4.0<=4.0.39")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash-static>4.1<=4.1.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash-static>4.2<=4.2.48")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bash-static>4.3<4.3.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux_base-c6<6.5_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
