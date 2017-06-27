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
  script_id(62806);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/07/20 01:56:56 $");

  script_cve_id("CVE-2012-0833", "CVE-2012-2687");

  script_name(english:"FreeBSD : apache22 -- several vulnerabilities (65539c54-2517-11e2-b9d6-20cf30e32f6d)");
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
"Apache HTTP SERVER PROJECT reports:low: XSS in mod_negotiation when
untrusted uploads are supported CVE-2012-2687 Possible XSS for sites
which use mod_negotiation and allow untrusted uploads to locations
which have MultiViews enabled. low: insecure LD_LIBRARY_PATH handling
CVE-2012-0883 This issue was already fixed in port version 2.2.22_5"
  );
  # http://www.freebsd.org/ports/portaudit/65539c54-2517-11e2-b9d6-20cf30e32f6d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d56d1b8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-event-mpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-itk-mpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-peruser-mpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-worker-mpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"apache22>2.2.0<2.2.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-event-mpm>2.2.0<2.2.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-itk-mpm>2.2.0<2.2.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-peruser-mpm>2.2.0<2.2.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-worker-mpm>2.2.0<2.2.23")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
