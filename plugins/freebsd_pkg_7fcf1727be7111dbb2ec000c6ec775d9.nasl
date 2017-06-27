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
  script_id(24365);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:31:56 $");

  script_cve_id("CVE-2007-0905", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988");
  script_xref(name:"Secunia", value:"24089");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (7fcf1727-be71-11db-b2ec-000c6ec775d9)");
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
"Multiple vulnerabilities have been found in PHP, including : buffer
overflows, stack overflows, format string, and information disclosure
vulnerabilities.

The session extension contained safe_mode and open_basedir bypasses,
but the FreeBSD Security Officer does not consider these real security
vulnerabilities, since safe_mode and open_basedir are insecure by
design and should not be relied upon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/4_4_5.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_1.php"
  );
  # http://www.freebsd.org/ports/portaudit/7fcf1727-be71-11db-b2ec-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00696e94"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php4-twig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-dtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-nms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-dtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-nms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"php5-imap<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-odbc<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-session<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-shmop<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-sqlite<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-wddx<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-odbc<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-session<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-shmop<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-wddx<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php4-twig>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php4-twig>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php4>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php4>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php5>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php5>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cgi>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cgi>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cli>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cli>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-dtc>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-dtc>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-horde>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-horde>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-nms>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-nms>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cgi>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cgi>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cli>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cli>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-dtc>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-dtc>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-horde>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-horde>=5<5.2.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-nms>=4<4.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-nms>=5<5.2.1_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
