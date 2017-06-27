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
  script_id(84282);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/09/26 19:18:36 $");

  script_cve_id("CVE-2015-3231", "CVE-2015-3232", "CVE-2015-3233", "CVE-2015-3234");

  script_name(english:"FreeBSD : drupal -- multiple vulnerabilities (d605edb1-1616-11e5-a000-d050996490d0)");
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
"Drupal development team reports : Impersonation (OpenID module -
Drupal 6 and 7 - Critical) A vulnerability was found in the OpenID
module that allows a malicious user to log in as other users on the
site, including administrators, and hijack their accounts.

This vulnerability is mitigated by the fact that the victim must have
an account with an associated OpenID identity from a particular set of
OpenID providers (including, but not limited to, Verisign,
LiveJournal, or StackExchange). Open redirect (Field UI module -
Drupal 7 - Less critical) The Field UI module uses a 'destinations'
query string parameter in URLs to redirect users to new destinations
after completing an action on a few administration pages. Under
certain circumstances, malicious users can use this parameter to
construct a URL that will trick users into being redirected to a 3rd
party website, thereby exposing the users to potential social
engineering attacks.

This vulnerability is mitigated by the fact that only sites with the
Field UI module enabled are affected.

Drupal 6 core is not affected, but see the similar advisory for the
Drupal 6 contributed CCK module : SA-CONTRIB-2015-126 Open redirect
(Overlay module - Drupal 7 - Less critical) The Overlay module
displays administrative pages as a layer over the current page (using
JavaScript), rather than replacing the page in the browser window. The
Overlay module does not sufficiently validate URLs prior to displaying
their contents, leading to an open redirect vulnerability.

This vulnerability is mitigated by the fact that it can only be used
against site users who have the 'Access the administrative overlay'
permission, and that the Overlay module must be enabled. Information
disclosure (Render cache system - Drupal 7 - Less critical) On sites
utilizing Drupal 7's render cache system to cache content on the site
by user role, private content viewed by user 1 may be included in the
cache and exposed to non-privileged users.

This vulnerability is mitigated by the fact that render caching is not
used in Drupal 7 core itself (it requires custom code or the
contributed Render Cache module to enable) and that it only affects
sites that have user 1 browsing the live site. Exposure is also
limited if an administrative role has been assigned to the user 1
account (which is done, for example, by the Standard install profile
that ships with Drupal core)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/SA-CORE-2015-002"
  );
  # http://www.freebsd.org/ports/portaudit/d605edb1-1616-11e5-a000-d050996490d0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?377efbbc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");
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

if (pkg_test(save_report:TRUE, pkg:"drupal6<6.36")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drupal7<7.38")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
