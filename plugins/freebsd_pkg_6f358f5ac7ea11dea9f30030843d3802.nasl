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
  script_id(42342);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/13 14:37:09 $");

  script_name(english:"FreeBSD : KDE -- multiple vulnerabilities (6f358f5a-c7ea-11de-a9f3-0030843d3802)");
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
"oCERT reports :

Ark input sanitization errors: The KDE archiving tool, Ark, performs
insufficient validation which leads to specially crafted archive
files, using unknown MIME types, to be rendered using a KHTML
instance, this can trigger uncontrolled XMLHTTPRequests to remote
sites.

IO Slaves input sanitization errors: KDE protocol handlers perform
insufficient input validation, an attacker can craft malicious URI
that would trigger JavaScript execution. Additionally the 'help://'
protocol handler suffer from directory traversal. It should be noted
that the scope of this issue is limited as the malicious URIs cannot
be embedded in Internet hosted content.

KMail input sanitization errors: The KDE mail client, KMail, performs
insufficient validation which leads to specially crafted email
attachments, using unknown MIME types, to be rendered using a KHTML
instance, this can trigger uncontrolled XMLHTTPRequests to remote
sites.

The exploitation of these vulnerabilities is unlikely according to
Portcullis and KDE but the execution of active content is nonetheless
unexpected and might pose a threat."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ocert.org/advisories/ocert-2009-015.html"
  );
  # http://www.freebsd.org/ports/portaudit/6f358f5a-c7ea-11de-a9f3-0030843d3802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1576fa0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kdebase-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"kdebase-runtime>=4.0.*<4.3.1_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kdelibs>=4.0.*<4.3.1_5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
