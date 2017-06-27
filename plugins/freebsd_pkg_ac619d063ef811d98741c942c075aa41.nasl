#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(37437);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2004-1029");

  script_name(english:"FreeBSD : jdk/jre -- Security Vulnerability With Java Plugin (ac619d06-3ef8-11d9-8741-c942c075aa41)");
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
"The Sun Java Plugin capability in Java 2 Runtime Environment (JRE)
1.4.2_01, 1.4.2_04, and possibly earlier versions, does not properly
restrict access between JavaScript and Java applets during data
transfer, which allows remote attackers to load unsafe classes and
execute arbitrary code."
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-26-57591-1&searchclause=%22category:security%22%20%22availability,%20security%22
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d26b9edd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/382072"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110125046627909
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110125046627909"
  );
  # http://www.freebsd.org/ports/portaudit/ac619d06-3ef8-11d9-8741-c942c075aa41.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd07783d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:diablo-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:diablo-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-blackdown-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-ibm-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-sun-jdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"jdk>=1.4.0<=1.4.2p6_6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jdk>=1.3.0<=1.3.1p9_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-jdk>=1.4.0<=1.4.2.05")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-jdk>=1.3.0<=1.3.1.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jdk>=1.4.0<=1.4.2.05")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jdk>=1.3.0<=1.3.1.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-blackdown-jdk>=1.3.0<=1.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-ibm-jdk>=1.3.0<=1.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"diablo-jdk>=1.3.1.0<=1.3.1.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"diablo-jre>=1.3.1.0<=1.3.1.0_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
