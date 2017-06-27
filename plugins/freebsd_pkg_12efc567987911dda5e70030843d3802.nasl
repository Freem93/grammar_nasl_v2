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
  script_id(34389);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/21 23:43:35 $");

  script_cve_id("CVE-2008-4791", "CVE-2008-4792", "CVE-2008-4793");
  script_xref(name:"Secunia", value:"32198");
  script_xref(name:"Secunia", value:"32200");
  script_xref(name:"Secunia", value:"32201");

  script_name(english:"FreeBSD : drupal -- multiple vulnerabilities (12efc567-9879-11dd-a5e7-0030843d3802)");
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
"The Drupal Project reports :

A logic error in the core upload module validation allowed
unprivileged users to attach files to content. Users can view files
attached to content which they do not otherwise have access to. If the
core upload module is not enabled, your site will not be affected.

A deficiency in the user module allowed users who had been blocked by
access rules to continue logging into the site under certain
conditions. If you do not use the 'access rules' functionality in
core, your site will not be affected.

The BlogAPI module does not implement correct validation for certain
content fields, allowing for values to be set for fields which would
otherwise be inaccessible on an internal Drupal form. We have hardened
these checks in BlogAPI module for this release, but the security team
would like to re-iterate that the 'Administer content with BlogAPI'
permission should only be given to trusted users. If the core BlogAPI
module is not enabled, your site will not be affected.

A weakness in the node module API allowed for node validation to be
bypassed in certain circumstances for contributed modules implementing
the API. Additional checks have been added to ensure that validation
is performed in all cases. This vulnerability only affects sites using
one of a very small number of contributed modules, all of which will
continue to work correctly with the improved API. None of them were
found vulnerable, so our correction is a preventative measure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/318706"
  );
  # http://www.freebsd.org/ports/portaudit/12efc567-9879-11dd-a5e7-0030843d3802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d44aaa38"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"drupal5<5.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drupal6<6.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
