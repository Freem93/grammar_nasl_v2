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
  script_id(61765);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/27 10:42:17 $");

  script_cve_id("CVE-2012-4377", "CVE-2012-4378", "CVE-2012-4379", "CVE-2012-4380", "CVE-2012-4381", "CVE-2012-4382");

  script_name(english:"FreeBSD : mediawiki -- multiple vulnerabilities (7c0fecd6-f42f-11e1-b17b-000c2977ec30)");
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
"MediaWiki reports :

(Bug 39700) Wikipedia administrator Writ Keeper discovered a stored
XSS (HTML injection) vulnerability. This was possible due to the
handling of link text on File: links for nonexistent files. MediaWiki
1.16 and later is affected.

(Bug 39180) User Fomafix reported several DOM-based XSS
vulnerabilities, made possible by a combination of loose filtering of
the uselang parameter, and JavaScript gadgets on various language
Wikipedias.

(Bug 39180) During internal review, it was discovered that CSRF
tokens, available via the api, were not protected with X-Frame-Options
headers. This could lead to a CSRF vulnerability if the API response
is embedded in an external website using using an iframe.

(Bug 39824) During internal review, it was discovered extensions were
not always allowed to prevent the account creation action. This
allowed users blocked by the GlobalBlocking extension to create
accounts.

(Bug 39184) During internal review, it was discovered that password
data was always saved to the local MediaWiki database even if
authentication was handled by an extension, such as LDAP. This could
allow a compromised MediaWiki installation to leak information about
user's LDAP passwords. Additionally, in situations when an
authentication plugin returned false in its strict function, this
would allow old passwords to be used for accounts that did not exist
in the external system, indefinitely.

(Bug 39823) During internal review, it was discovered that metadata
about blocks, hidden by a user with suppression rights, was visible to
administrators."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=39700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=37587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=39180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=39824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=39184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=39823"
  );
  # http://www.freebsd.org/ports/portaudit/7c0fecd6-f42f-11e1-b17b-000c2977ec30.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a446847a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"mediawiki>=1.19<1.19.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mediawiki>=1.18<1.18.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
