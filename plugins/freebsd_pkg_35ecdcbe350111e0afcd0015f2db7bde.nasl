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
  script_id(51950);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/21 23:48:19 $");

  script_cve_id("CVE-2010-2901", "CVE-2010-4040", "CVE-2010-4042", "CVE-2010-4199", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");

  script_name(english:"FreeBSD : webkit-gtk2 -- Multiple vurnabilities. (35ecdcbe-3501-11e0-afcd-0015f2db7bde)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gustavo Noronha Silva reports :

This release has essentially security fixes. Refer to the
WebKit/gtk/NEWS file inside the tarball for details. We would like to
thank the Red Hat security team (Huzaifa Sidhpurwala in particular)
and Michael Gilbert from Debian for their help in checking (and
pushing!) security issues affecting the WebKitGTK+ stable branch for
this release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.webkit.org/show_bug.cgi?id=48328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.webkit.org/show_bug.cgi?id=50710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.webkit.org/show_bug.cgi?id=50840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.webkit.org/show_bug.cgi?id=50932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.webkit.org/show_bug.cgi?id=51993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.webkit.org/show_bug.cgi?id=53265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.webkit.org/show_bug.cgi?id=53276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://permalink.gmane.org/gmane.os.opendarwin.webkit.gtk/405"
  );
  # http://www.freebsd.org/ports/portaudit/35ecdcbe-3501-11e0-afcd-0015f2db7bde.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7f1c207"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:webkit-gtk2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"webkit-gtk2<1.2.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
