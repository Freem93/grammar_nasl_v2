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
  script_id(86858);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/12 15:02:07 $");

  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4807", "CVE-2015-4815", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4913");

  script_name(english:"FreeBSD : MySQL - Multiple vulnerabilities (851a0eea-88aa-11e5-90e7-b499baebfeaf)");
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
"Oracle reports :

Critical Patch Update: MySQL Server, version(s) 5.5.45 and prior,
5.6.26 and prior"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75a4a4fb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-5546-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10022-release-notes/"
  );
  # https://www.percona.com/doc/percona-server/5.5/release-notes/Percona-Server-5.5.46-37.5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e29b246f"
  );
  # https://www.percona.com/doc/percona-server/5.6/release-notes/Percona-Server-5.6.27-75.0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ac422d9"
  );
  # http://www.freebsd.org/ports/portaudit/851a0eea-88aa-11e5-90e7-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?306c680b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb100-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb100-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql55-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/12");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb-client<5.3.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb-server<5.3.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb55-client<5.5.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb55-server<5.5.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb100-client<10.0.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb100-server<10.0.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql55-client<5.5.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql55-server<5.5.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-client<5.6.27")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.27")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-client<5.5.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-server<5.5.46")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-client<5.6.27")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-server<5.6.27")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
