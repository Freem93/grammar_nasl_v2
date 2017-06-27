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
  script_id(90052);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/19 14:14:41 $");

  script_cve_id("CVE-2016-2324");

  script_name(english:"FreeBSD : git -- integer overflow (d2a84feb-ebe0-11e5-92ce-002590263bf5)");
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
"Debian reports :

integer overflow due to a loop which adds more to 'len'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2324"
  );
  # https://github.com/git/git/commit/9831e92bfa833ee9c0ce464bbc2f941ae6c2698d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?060b5973"
  );
  # http://www.freebsd.org/ports/portaudit/d2a84feb-ebe0-11e5-92ce-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0eb7c929"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:git-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:git-subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");
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

if (pkg_test(save_report:TRUE, pkg:"git<2.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.5.0<2.5.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.6.0<2.6.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.7.0<2.7.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui<2.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.5.0<2.5.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.6.0<2.6.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.7.0<2.7.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite<2.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.5.0<2.5.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.6.0<2.6.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.7.0<2.7.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-subversion<2.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-subversion>=2.5.0<2.5.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-subversion>=2.6.0<2.6.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-subversion>=2.7.0<2.7.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
