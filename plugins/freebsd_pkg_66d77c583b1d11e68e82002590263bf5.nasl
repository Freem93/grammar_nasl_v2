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
  script_id(91839);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2015-8874", "CVE-2016-5766", "CVE-2016-5767", "CVE-2016-5768", "CVE-2016-5769", "CVE-2016-5770", "CVE-2016-5771", "CVE-2016-5772", "CVE-2016-5773");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (66d77c58-3b1d-11e6-8e82-002590263bf5)");
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

- Core :

- Fixed bug #72268 (Integer Overflow in nl2br())

- Fixed bug #72275 (Integer Overflow in json_encode()/ json_decode()/
json_utf8_to_utf16())

- Fixed bug #72400 (Integer Overflow in addcslashes/ addslashes)

- Fixed bug #72403 (Integer Overflow in Length of String-typed ZVAL)

- GD :

- Fixed bug #66387 (Stack overflow with imagefilltoborder)
(CVE-2015-8874)

- Fixed bug #72298 (pass2_no_dither out-of-bounds access)

- Fixed bug #72339 (Integer Overflow in _gd2GetHeader() resulting in
heap overflow) (CVE-2016-5766)

- Fixed bug #72407 (NULL pointer Dereference at _gdScaleVert)

- Fixed bug #72446 (Integer Overflow in gdImagePaletteToTrueColor()
resulting in heap overflow) (CVE-2016-5767)

- mbstring :

- Fixed bug #72402 (_php_mb_regex_ereg_replace_exec - double free)
(CVE-2016-5768)

- mcrypt :

- Fixed bug #72455 (Heap Overflow due to integer overflows)
(CVE-2016-5769)

- Phar :

- Fixed bug #72321 (invalid free in phar_extract_file()). (PHP 5.6/7.0
only)

- SPL :

- Fixed bug #72262 (int/size_t confusion in SplFileObject::fread)
(CVE-2016-5770)

- Fixed bug #72433 (Use After Free Vulnerability in PHP's GC algorithm
and unserialize) (CVE-2016-5771)

- WDDX :

- Fixed bug #72340 (Double Free Courruption in wddx_deserialize)
(CVE-2016-5772)

- zip :

- Fixed bug #72434 (ZipArchive class Use After Free Vulnerability in
PHP's GC algorithm and unserialize). (CVE-2016-5773)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=210491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=210502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.37"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.6.23"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-7.php#7.0.8"
  );
  # http://www.freebsd.org/ports/portaudit/66d77c58-3b1d-11e6-8e82-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99385229"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");
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

if (pkg_test(save_report:TRUE, pkg:"php55<5.5.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-gd<5.5.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-mbstring<5.5.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-wddx<5.5.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-zip<5.5.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56<5.6.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-gd<5.6.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-mbstring<5.6.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-phar<5.6.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-wddx<5.6.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-zip<5.6.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70<7.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-gd<7.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-mbstring<7.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-phar<7.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-wddx<7.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-zip<7.0.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
