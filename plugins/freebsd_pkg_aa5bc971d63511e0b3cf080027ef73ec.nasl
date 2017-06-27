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
  script_id(56081);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/13 14:37:09 $");

  script_name(english:"FreeBSD : nss/ca_root_nss -- fraudulent certificates issued by DigiNotar.nl (aa5bc971-d635-11e0-b3cf-080027ef73ec)");
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
"Heather Adkins, Google's Information Security Manager, reported that
Google received

[...] reports of attempted SSL man-in-the-middle (MITM) attacks
against Google users, whereby someone tried to get between them and
encrypted Google services. The people affected were primarily located
in Iran. The attacker used a fraudulent SSL certificate issued by
DigiNotar, a root certificate authority that should not issue
certificates for Google (and has since revoked it). [...]

VASCO Data Security International Inc., owner of DigiNotar, issued a
press statement confirming this incident :

On July 19th 2011, DigiNotar detected an intrusion into its
Certificate Authority (CA) infrastructure, which resulted in the
fraudulent issuance of public key certificate requests for a number of
domains, including Google.com. [...] an external security audit
concluded that all fraudulently issued certificates were revoked.
Recently, it was discovered that at least one fraudulent certificate
had not been revoked at the time. [...]

Mozilla, maintainer of the NSS package, from which FreeBSD derived
ca_root_nss, stated that they :

revoked our trust in the DigiNotar certificate authority from all
Mozilla software. This is not a temporary suspension, it is a complete
removal from our trusted root program. Complete revocation of trust is
a decision we treat with careful consideration, and employ as a last
resort.

Three central issues informed our decision :

- Failure to notify. [...]

- The scope of the breach remains unknown. [...]

- The attack is not theoretical."
  );
  # http://www.vasco.com/company/press_room/news_archive/2011/news_diginotar_reports_security_incident.aspx
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baa49230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-34.html"
  );
  # http://googleonlinesecurity.blogspot.com/2011/08/update-on-attempted-man-in-middle.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3fc8e9a"
  );
  # http://www.freebsd.org/ports/portaudit/aa5bc971-d635-11e0-b3cf-080027ef73ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ea6c31a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ca_root_nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"nss<3.12.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ca_root_nss<3.12.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox>3.6.*,1<3.6.22,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox>4.0.*,1<6.0.2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.3.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<3.6.22,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>3.1.*<3.1.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>5.0.*<6.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<3.1.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.3.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
