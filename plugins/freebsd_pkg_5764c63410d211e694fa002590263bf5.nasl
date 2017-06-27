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
  script_id(90844);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2016-3074");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (5764c634-10d2-11e6-94fa-002590263bf5)");
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

- BCMath :

- Fixed bug #72093 (bcpowmod accepts negative scale and corrupts _one_
definition).

- Exif :

- Fixed bug #72094 (Out of bounds heap read access in exif header
processing).

- GD :

- Fixed bug #71912 (libgd: signedness vulnerability). (CVE-2016-3074)

- Intl :

- Fixed bug #72061 (Out-of-bounds reads in zif_grapheme_stripos with
negative offset).

- XML :

- Fixed bug #72099 (xml_parse_into_struct segmentation fault)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=209145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-7.php#7.0.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.6.21"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.5.35"
  );
  # http://www.freebsd.org/ports/portaudit/5764c634-10d2-11e6-94fa-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2846ac0d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");
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

if (pkg_test(save_report:TRUE, pkg:"php70<7.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-bcmath<7.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-exif<7.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-gd<7.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70-xml<7.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56<5.6.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-bcmath<5.6.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-exif<5.6.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-gd<5.6.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-xml<5.6.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55<5.5.35")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-bcmath<5.5.35")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-exif<5.5.35")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-gd<5.5.35")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-xml<5.5.35")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
