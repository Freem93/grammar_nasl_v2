#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
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
  script_id(96510);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/16 15:05:11 $");

  script_cve_id("CVE-2016-3492", "CVE-2016-5616", "CVE-2016-5617", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6663", "CVE-2016-6664", "CVE-2016-8283");

  script_name(english:"FreeBSD : MySQL -- multiple vulnerabilities (22373c43-d728-11e6-a9a5-b499baebfeaf)");
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
"The MySQL project reports :

- CVE-2016-3492: Remote security vulnerability in 'Server: Optimizer'
sub component.

- CVE-2016-5616, CVE-2016-6663: Race condition allows local users with
certain permissions to gain privileges by leveraging use of
my_copystat by REPAIR TABLE to repair a MyISAM table.

- CVE-2016-5617, CVE-2016-6664: mysqld_safe, when using file-based
logging, allows local users with access to the mysql account to gain
root privileges via a symlink attack on error logs and possibly other
files.

- CVE-2016-5624: Remote security vulnerability in 'Server: DML' sub
component.

- CVE-2016-5626: Remote security vulnerability in 'Server: GIS' sub
component.

- CVE-2016-5629: Remote security vulnerability in 'Server: Federated'
sub component.

- CVE-2016-8283: Remote security vulnerability in 'Server: Types' sub
component."
  );
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html#AppendixMSQL
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ad1fd2e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10028-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-5552-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10118-release-notes/"
  );
  # http://www.freebsd.org/ports/portaudit/22373c43-d728-11e6-a9a5-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20ca9702"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb100-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb100-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql55-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb55-client<5.5.52")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb55-server<5.5.52")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb100-client<10.0.28")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb100-server<10.0.28")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-client<10.1.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-server<10.1.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql55-client<5.5.52")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql55-server<5.5.52")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-client<5.6.33")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.33")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-client<5.7.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-server<5.7.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-client<5.5.51.38.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-server<5.5.51.38.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-client<5.6.32.78.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-server<5.6.32.78.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
