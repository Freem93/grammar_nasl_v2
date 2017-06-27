#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(69087);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/09/22 00:06:44 $");

  script_cve_id("CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-2205");

  script_name(english:"FreeBSD : wordpress -- multiple vulnerabilities (049332d2-f6e1-11e2-82f3-000c29ee3065)");
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
"The wordpress development team reports :

- Blocking server-side request forgery attacks, which could
potentially enable an attacker to gain access to a site

- Disallow contributors from improperly publishing posts

- An update to the SWFUpload external library to fix cross-site
scripting vulnerabilities

- Prevention of a denial of service attack, affecting sites using
password-protected posts

- An update to an external TinyMCE library to fix a cross-site
scripting vulnerability

- Multiple fixes for cross-site scripting

- Avoid disclosing a full file path when a upload fails"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wordpress.org/news/2013/06/wordpress-3-5-2/"
  );
  # http://www.freebsd.org/ports/portaudit/049332d2-f6e1-11e2-82f3-000c29ee3065.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab81b7b4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-wordpress-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-wordpress-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"wordpress<3.5.2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress-zh_CN<3.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress-zh_TW<3.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-wordpress<3.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-wordpress<3.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-wordpress<3.5.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
