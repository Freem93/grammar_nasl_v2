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
  script_id(92574);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/10/24 13:46:11 $");

  script_cve_id("CVE-2015-8879", "CVE-2016-5385", "CVE-2016-5399", "CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (b6402385-533b-11e6-a7bd-14dae9d210b8) (httpoxy)");
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
"PHP reports :

- Fixed bug #69975 (PHP segfaults when accessing nvarchar(max) defined
columns)

- Fixed bug #72479 (Use After Free Vulnerability in SNMP with GC and
unserialize()).

- Fixed bug #72512 (gdImageTrueColorToPaletteBody allows arbitrary
write/read access).

- Fixed bug #72519 (imagegif/output out-of-bounds access).

- Fixed bug #72520 (Stack-based buffer overflow vulnerability in
php_stream_zip_opener).

- Fixed bug #72533 (locale_accept_from_http out-of-bounds access).

- Fixed bug #72541 (size_t overflow lead to heap corruption).

- Fixed bug #72551, bug #72552 (Incorrect casting from size_t to int
lead to heap overflow in mdecrypt_generic).

- Fixed bug #72558 (Integer overflow error within
_gdContributionsAlloc()).

- Fixed bug #72573 (HTTP_PROXY is improperly trusted by some PHP
libraries and applications).

- Fixed bug #72603 (Out of bound read in
exif_process_IFD_in_MAKERNOTE).

- Fixed bug #72606 (heap-buffer-overflow (write) simplestring_addn
simplestring.c).

- Fixed bug #72613 (Inadequate error handling in bzread()).

- Fixed bug #72618 (NULL pointer Dereference in
exif_process_user_comment)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.5.38"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.6.24"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-7.php#7.0.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2016/q3/121"
  );
  # http://www.freebsd.org/ports/portaudit/b6402385-533b-11e6-a7bd-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c004088c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
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

if (pkg_test(save_report:TRUE, pkg:"php55<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-curl<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-bz2<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-bz2<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-bz2<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-exif<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-exif<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-exif<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-gd<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-gd<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-gd<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-mcrypt<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-odbc<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-odbc<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-odbc<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-snmp<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-snmp<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-snmp<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-xmlrpc<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-xmlrpc<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-xmlrpc<7.0.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-zip<5.5.38")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-zip<5.6.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-zip<7.0.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
