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
  script_id(39784);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2009-2372", "CVE-2009-2373", "CVE-2009-2374");
  script_xref(name:"Secunia", value:"35681");

  script_name(english:"FreeBSD : drupal -- multiple vulnerabilities (be927298-6f97-11de-b444-001372fd0af2)");
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
"The Drupal Security Team reports :

Cross-site scripting

The Forum module does not correctly handle certain arguments obtained
from the URL. By enticing a suitably privileged user to visit a
specially crafted URL, a malicious user is able to insert arbitrary
HTML and script code into forum pages. Such a cross-site scripting
attack may lead to the malicious user gaining administrative access.
Wikipedia has more information about cross-site scripting (XSS).

User signatures have no separate input format, they use the format of
the comment with which they are displayed. A user will no longer be
able to edit a comment when an administrator changes the comment's
input format to a format that is not accessible to the user. However
they will still be able to modify their signature, which will then be
processed by the new input format.

If the new format is very permissive, via their signature, the user
may be able to insert arbitrary HTML and script code into pages or,
when the PHP filter is enabled for the new format, execute PHP code.
This issue affects Drupal 6.x only.

When an anonymous user fails to login due to mistyping his username or
password, and the page he is on contains a sortable table, the
(incorrect) username and password are included in links on the table.
If the user visits these links the password may then be leaked to
external sites via the HTTP referer.

In addition, if the anonymous user is enticed to visit the site via a
specially crafted URL while the Drupal page cache is enabled, a
malicious user might be able to retrieve the (incorrect) username and
password from the page cache."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/507572"
  );
  # http://www.freebsd.org/ports/portaudit/be927298-6f97-11de-b444-001372fd0af2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b46d26f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 94, 255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"drupal5<5.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drupal6<6.13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
