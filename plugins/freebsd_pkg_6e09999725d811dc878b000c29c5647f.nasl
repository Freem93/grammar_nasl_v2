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
  script_id(25633);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:31:55 $");

  script_cve_id("CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3474", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");

  script_name(english:"FreeBSD : gd -- multiple vulnerabilities (6e099997-25d8-11dc-878b-000c29c5647f)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gd had been reported vulnerable to several vulnerabilities :

- CVE-2007-3472: Integer overflow in gdImageCreateTrueColor function
in the GD Graphics Library (libgd) before 2.0.35 allows user-assisted
remote attackers has unspecified attack vectors and impact.

- CVE-2007-3473: The gdImageCreateXbm function in the GD Graphics
Library (libgd) before 2.0.35 allows user-assisted remote attackers to
cause a denial of service (crash) via unspecified vectors involving a
gdImageCreate failure.

- CVE-2007-3474: Multiple unspecified vulnerabilities in the GIF
reader in the GD Graphics Library (libgd) before 2.0.35 allow
user-assisted remote attackers to have unspecified attack vectors and
impact.

- CVE-2007-3475: The GD Graphics Library (libgd) before 2.0.35 allows
user-assisted remote attackers to cause a denial of service (crash)
via a GIF image that has no global color map.

- CVE-2007-3476: Array index error in gd_gif_in.c in the GD Graphics
Library (libgd) before 2.0.35 allows user-assisted remote attackers to
cause a denial of service (crash and heap corruption) via large color
index values in crafted image data, which results in a segmentation
fault.

- CVE-2007-3477: The (a) imagearc and (b) imagefilledarc functions in
GD Graphics Library (libgd) before 2.0.35 allows attackers to cause a
denial of service (CPU consumption) via a large (1) start or (2) end
angle degree value.

- CVE-2007-3478: Race condition in gdImageStringFTEx
(gdft_draw_bitmap) in gdft.c in the GD Graphics Library (libgd) before
2.0.35 allows user-assisted remote attackers to cause a denial of
service (crash) via unspecified vectors, possibly involving truetype
font (TTF) support."
  );
  # http://www.libgd.org/ReleaseNote020035
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fa888e5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.frsirt.com/english/advisories/2007/2336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.libgd.org/?do=details&task_id=89"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.libgd.org/?do=details&task_id=94"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.libgd.org/?do=details&task_id=70"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.libgd.org/?do=details&task_id=87"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.libgd.org/?do=details&task_id=92"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.libgd.org/?do=details&task_id=74"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.libgd.org/?do=details&task_id=48"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.php.net/bug.php?id=40578"
  );
  # http://www.freebsd.org/ports/portaudit/6e099997-25d8-11dc-878b-000c29c5647f.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?249b4ca0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(189, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/01");
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

if (pkg_test(save_report:TRUE, pkg:"gd<2.0.35,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
