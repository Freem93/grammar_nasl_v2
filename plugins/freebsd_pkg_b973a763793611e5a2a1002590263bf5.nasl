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
  script_id(86554);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/29 14:44:44 $");

  script_cve_id("CVE-2015-8001", "CVE-2015-8002", "CVE-2015-8003", "CVE-2015-8004", "CVE-2015-8005", "CVE-2015-8006", "CVE-2015-8007", "CVE-2015-8008", "CVE-2015-8009");

  script_name(english:"FreeBSD : mediawiki -- multiple vulnerabilities (b973a763-7936-11e5-a2a1-002590263bf5)");
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

Wikipedia user RobinHood70 reported two issues in the chunked upload
API. The API failed to correctly stop adding new chunks to the upload
when the reported size was exceeded (T91203), allowing a malicious
users to upload add an infinite number of chunks for a single file
upload. Additionally, a malicious user could upload chunks of 1 byte
for very large files, potentially creating a very large number of
files on the server's filesystem (T91205).

Internal review discovered that it is not possible to throttle file
uploads.

Internal review discovered a missing authorization check when removing
suppression from a revision. This allowed users with the
'viewsuppressed' user right but not the appropriate 'suppressrevision'
user right to unsuppress revisions.

Richard Stanway from teamliquid.net reported that thumbnails of PNG
files generated with ImageMagick contained the local file path in the
image metadata."
  );
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-October/000181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da85c1ce"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T91203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T91205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T91850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T95589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T108616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2015/10/29/14"
  );
  # http://www.freebsd.org/ports/portaudit/b973a763-7936-11e5-a2a1-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ca1d2e5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki124");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki125");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");
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

if (pkg_test(save_report:TRUE, pkg:"mediawiki123<1.23.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mediawiki124<1.24.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mediawiki125<1.25.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
