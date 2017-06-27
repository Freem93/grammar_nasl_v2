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
  script_id(84326);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/19 14:14:41 $");

  script_cve_id("CVE-2015-4643", "CVE-2015-4644");

  script_name(english:"FreeBSD : php5 -- multiple vulnerabilities (cdff0af2-1492-11e5-a1cf-002590263bf5)");
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
"The PHP project reports :

DOM and GD :

- Fixed bug #69719 (Incorrect handling of paths with NULs).

FTP :

- Improved fix for bug #69545 (Integer overflow in ftp_genlist()
resulting in heap overflow). (CVE-2015-4643)

Postgres :

- Fixed bug #69667 (segfault in php_pgsql_meta_data). (CVE-2015-4644)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.4.42"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.5.26"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.6.10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openwall.com/lists/oss-security/2015/06/18/3"
  );
  # http://www.freebsd.org/ports/portaudit/cdff0af2-1492-11e5-a1cf-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1b7361d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-psql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/23");
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

if (pkg_test(save_report:TRUE, pkg:"php5-dom<5.4.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-ftp<5.4.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-gd<5.4.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-pgsql<5.4.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-dom<5.5.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-ftp<5.5.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-gd<5.5.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-pgsql<5.5.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-dom<5.6.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-ftp<5.6.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-gd<5.6.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-psql<5.6.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
