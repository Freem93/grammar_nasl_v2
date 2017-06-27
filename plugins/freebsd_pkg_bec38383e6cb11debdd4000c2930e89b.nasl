#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(43127);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/13 14:23:43 $");

  script_cve_id("CVE-2009-4786", "CVE-2009-4787", "CVE-2009-4788");
  script_xref(name:"Secunia", value:"37349");

  script_name(english:"FreeBSD : pligg -- XSS and Cross-Site Request Forgery (bec38383-e6cb-11de-bdd4-000c2930e89b)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"secunia reports :

Russ McRee has discovered some vulnerabilities in Pligg, which can be
exploited by malicious people to conduct cross-site scripting and
request forgery attacks.

Input passed via the 'Referer' HTTP header to various scripts (e.g.
admin/admin_config.php, admin/admin_modules.php, delete.php,
editlink.php, submit.php, submit_groups.php,
user_add_remove_links.php, and user_settings.php) is not properly
sanitised before being returned to the user. This can be exploited to
execute arbitrary HTML and script code in a user's browser session in
context of an affected site.

The application allows users to perform certain actions via HTTP
requests without performing any validity checks to verify the
requests. This can be exploited to e.g. create an arbitrary user with
administrative privileges if a logged-in administrative user visits a
malicious website."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pligg.com/blog/775/pligg-cms-1-0-3-release/"
  );
  # http://www.freebsd.org/ports/portaudit/bec38383-e6cb-11de-bdd4-000c2930e89b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd37509c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pligg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"pligg<1.0.3b")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
