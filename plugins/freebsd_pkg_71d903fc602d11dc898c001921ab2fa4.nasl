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
  script_id(26038);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:31:55 $");

  script_cve_id("CVE-2007-2872", "CVE-2007-3378", "CVE-2007-3806", "CVE-2007-3996", "CVE-2007-3997", "CVE-2007-3998", "CVE-2007-4652", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4659", "CVE-2007-4660", "CVE-2007-4661", "CVE-2007-4662", "CVE-2007-4663", "CVE-2007-4670");
  script_xref(name:"Secunia", value:"26642");

  script_name(english:"FreeBSD : php -- multiple vulnerabilities (71d903fc-602d-11dc-898c-001921ab2fa4)");
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
"The PHP development team reports :

Security Enhancements and Fixes in PHP 5.2.4 :

- Fixed a floating point exception inside wordwrap() (Reported by
Mattias Bengtsson)

- Fixed several integer overflows inside the GD extension (Reported by
Mattias Bengtsson)

- Fixed size calculation in chunk_split() (Reported by Gerhard Wagner)

- Fixed integer overflow in str[c]spn(). (Reported by Mattias
Bengtsson)

- Fixed money_format() not to accept multiple %i or %n tokens.
(Reported by Stanislav Malyshev)

- Fixed zend_alter_ini_entry() memory_limit interruption
vulnerability. (Reported by Stefan Esser)

- Fixed INFILE LOCAL option handling with MySQL extensions not to be
allowed when open_basedir or safe_mode is active. (Reported by Mattias
Bengtsson)

- Fixed session.save_path and error_log values to be checked against
open_basedir and safe_mode (CVE-2007-3378) (Reported by Maksymilian
Arciemowicz)

- Fixed a possible invalid read in glob() win32 implementation
(CVE-2007-3806) (Reported by shinnai)

- Fixed a possible buffer overflow in php_openssl_make_REQ (Reported
by zatanzlatan at hotbrev dot com)

- Fixed an open_basedir bypass inside glob() function (Reported by dr
at peytz dot dk)

- Fixed a possible open_basedir bypass inside session extension when
the session file is a symlink (Reported by c dot i dot morris at
durham dot ac dot uk)

- Improved fix for MOPB-03-2007.

- Corrected fix for CVE-2007-2872."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/4_4_8.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_4.php"
  );
  # http://www.freebsd.org/ports/portaudit/71d903fc-602d-11dc-898c-001921ab2fa4.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d31a7c47"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 22, 119, 189, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");
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

if (pkg_test(save_report:TRUE, pkg:"php5<5.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4<4.4.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
