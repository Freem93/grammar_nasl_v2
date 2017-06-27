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
  script_id(88671);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/10/19 14:02:55 $");

  script_cve_id("CVE-2015-8383", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8393", "CVE-2015-8394", "CVE-2016-2554");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (85eb4e46-cf16-11e5-840f-485d605f4717)");
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

- Core :

- Fixed bug #71039 (exec functions ignore length but look for NULL
termination).

- Fixed bug #71323 (Output of stream_get_meta_data can be falsified by
its input).

- Fixed bug #71459 (Integer overflow in iptcembed()).

- PCRE :

- Upgraded bundled PCRE library to 8.38.(CVE-2015-8383, CVE-2015-8386,
CVE-2015-8387, CVE-2015-8389, CVE-2015-8390, CVE-2015-8391,
CVE-2015-8393, CVE-2015-8394)

- Phar :

- Fixed bug #71354 (Heap corruption in tar/zip/phar parser).

- Fixed bug #71391 (NULL pointer Dereference in
phar_tar_setupmetadata()).

- Fixed bug #71488 (Stack overflow when decompressing tar archives).
(CVE-2016-2554)

- WDDX :

- Fixed bug #71335 (Type Confusion in WDDX Packet Deserialization)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.6.18"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.32"
  );
  # http://www.freebsd.org/ports/portaudit/85eb4e46-cf16-11e5-840f-485d605f4717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f236751f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56-wddx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/10");
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

if (pkg_test(save_report:TRUE, pkg:"php55<5.5.32")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-phar<5.5.32")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55-wddx<5.5.32")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56<5.6.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-phar<5.6.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56-wddx<5.6.18")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
