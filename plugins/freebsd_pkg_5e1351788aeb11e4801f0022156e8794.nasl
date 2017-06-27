#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(80350);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/05 13:35:45 $");

  script_cve_id("CVE-2014-9033", "CVE-2014-9034", "CVE-2014-9035", "CVE-2014-9036", "CVE-2014-9037", "CVE-2014-9038", "CVE-2014-9039");

  script_name(english:"FreeBSD : wordpress -- multiple vulnerabilities (5e135178-8aeb-11e4-801f-0022156e8794)");
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
"MITRE reports :

wp-login.php in WordPress before 3.7.5, 3.8.x before 3.8.5, 3.9.x
before 3.9.3, and 4.x before 4.0.1 might allow remote attackers to
reset passwords by leveraging access to an e-mail account that
received a password-reset message.

wp-includes/http.php in WordPress before 3.7.5, 3.8.x before 3.8.5,
3.9.x before 3.9.3, and 4.x before 4.0.1 allows remote attackers to
conduct server-side request forgery (SSRF) attacks by referring to a
127.0.0.0/8 resource.

WordPress before 3.7.5, 3.8.x before 3.8.5, 3.9.x before 3.9.3, and
4.x before 4.0.1 might allow remote attackers to obtain access to an
account idle since 2008 by leveraging an improper PHP dynamic type
comparison for an MD5 hash.

Cross-site scripting (XSS) vulnerability in WordPress before 3.7.5,
3.8.x before 3.8.5, 3.9.x before 3.9.3, and 4.x before 4.0.1 allows
remote attackers to inject arbitrary web script or HTML via a crafted
Cascading Style Sheets (CSS) token sequence in a post.

Cross-site scripting (XSS) vulnerability in Press This in WordPress
before 3.7.5, 3.8.x before 3.8.5, 3.9.x before 3.9.3, and 4.x before
4.0.1 allows remote attackers to inject arbitrary web script or HTML
via unspecified vectors

wp-includes/class-phpass.php in WordPress before 3.7.5, 3.8.x before
3.8.5, 3.9.x before 3.9.3, and 4.x before 4.0.1 allows remote
attackers to cause a denial of service (CPU consumption) via a long
password that is improperly handled during hashing, a similar issue to
CVE-2014-9016.

Cross-site request forgery (CSRF) vulnerability in wp-login.php in
WordPress 3.7.4, 3.8.4, 3.9.2, and 4.0 allows remote attackers to
hijack the authentication of arbitrary users for requests that reset
passwords."
  );
  # http://www.freebsd.org/ports/portaudit/5e135178-8aeb-11e4-801f-0022156e8794.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73ec5e89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"wordpress<3.7.5,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wordpress>=3.8,1<3.8.5,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wordpress>=3.9,1<3.9.3,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wordpress>=4.0,1<4.0.1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress<3.7.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress>=3.8<3.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress>=3.9<3.9.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress>=4.0<4.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-wordpress<3.7.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-wordpress>=3.8<3.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-wordpress>=3.9<3.9.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-wordpress>=4.0<4.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-wordpress<3.7.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-wordpress>=3.8<3.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-wordpress>=3.9<3.9.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-wordpress>=4.0<4.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-wordpress<3.7.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-wordpress>=3.8<3.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-wordpress>=3.9<3.9.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-wordpress>=4.0<4.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
