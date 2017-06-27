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
  script_id(27551);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2007-5593", "CVE-2007-5594", "CVE-2007-5595", "CVE-2007-5596", "CVE-2007-5597");
  script_xref(name:"Secunia", value:"27290");
  script_xref(name:"Secunia", value:"27292");

  script_name(english:"FreeBSD : drupal --- multiple vulnerabilities (9c00d446-8208-11dc-9283-0016179b2dd5)");
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

In some circumstances Drupal allows user-supplied data to become part
of response headers. As this user-supplied data is not always properly
escaped, this can be exploited by malicious users to execute HTTP
response splitting attacks which may lead to a variety of issues,
among them cache poisoning, cross-user defacement and injection of
arbitrary code.

The Drupal installer allows any visitor to provide credentials for a
database when the site's own database is not reachable. This allows
attackers to run arbitrary code on the site's server. An immediate
workaround is the removal of the file install.php in the Drupal root
directory.

The allowed extension list of the core Upload module contains the
extension HTML by default. Such files can be used to execute arbitrary
script code in the context of the affected site when a user views the
file. Revoking upload permissions or removing the .html extension from
the allowed extension list will stop uploads of malicious files. but
will do nothing to protect your site againstfiles that are already
present. Carefully inspect the file system path for any HTML files. We
recommend you remove any HTML file you did not update yourself. You
should look for , CSS includes, JavaScript includes, and onerror=''
attributes if you need to review files individually.

The Drupal Forms API protects against cross site request forgeries
(CSRF), where a malicous site can cause a user to unintentionally
submit a form to a site where he is authenticated. The user deletion
form does not follow the standard Forms API submission model and is
therefore not protected against this type of attack. A CSRF attack may
result in the deletion of users.

The publication status of comments is not passed during the
hook_comments API operation, causing various modules that rely on the
publication status (such as Organic groups, or Subscriptions) to mail
out unpublished comments."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/184315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/184316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/184348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/184354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/184320"
  );
  # http://www.freebsd.org/ports/portaudit/9c00d446-8208-11dc-9283-0016179b2dd5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49bff90d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(79, 94, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
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

if (pkg_test(save_report:TRUE, pkg:"drupal4<4.7.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drupal5<5.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
