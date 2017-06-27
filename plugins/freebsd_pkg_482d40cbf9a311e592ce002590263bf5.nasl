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
  script_id(90335);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/05 21:32:30 $");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (482d40cb-f9a3-11e5-92ce-002590263bf5)");
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
"The PHP Group reports :

- Fileinfo :

- Fixed bug #71527 (Buffer over-write in finfo_open with malformed
magic file).

- mbstring :

- Fixed bug #71906 (AddressSanitizer: negative-size-param (-1) in
mbfl_strcut).

- Phar :

- Fixed bug #71860 (Invalid memory write in phar on filename with \0
in name).

- SNMP :

- Fixed bug #71704 (php_snmp_error() Format String Vulnerability).

- Standard :

- Fixed bug #71798 (Integer Overflow in php_raw_url_encode)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=208465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-7.php#7.0.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.6.20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.34"
  );
  # http://www.freebsd.org/ports/portaudit/482d40cb-f9a3-11e5-92ce-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1590af50"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"php70<7.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-fileinfo<7.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-mbstring<7.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-phar<7.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-snmp<7.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56<5.6.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-fileinfo<5.6.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-mbstring<5.6.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-phar<5.6.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-snmp<5.6.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55<5.5.34")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-fileinfo<5.5.34")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-mbstring<5.5.34")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-phar<5.5.34")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-snmp<5.5.34")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
