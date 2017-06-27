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
  script_id(61522);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/21 23:52:44 $");

  script_cve_id("CVE-2012-3422", "CVE-2012-3423");

  script_name(english:"FreeBSD : Several vulnerabilities found in IcedTea-Web (55b498e2-e56c-11e1-bbd5-001c25e46b1d)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The IcedTea project team reports :

CVE-2012-3422: Use of uninitialized instance pointers

An uninitialized pointer use flaw was found in IcedTea-Web web browser
plugin. A malicious web page could use this flaw make IcedTea-Web
browser plugin pass invalid pointer to a web browser. Depending on the
browser used, it may cause the browser to crash or possibly execute
arbitrary code.

The get_cookie_info() and get_proxy_info() call
getFirstInTableInstance() with the instance_to_id_map hash as a
parameter. If instance_to_id_map is empty (which can happen when
plugin was recently removed), getFirstInTableInstance() returns an
uninitialized pointer.

CVE-2012-3423: Incorrect handling of non 0-terminated strings

It was discovered that the IcedTea-Web web browser plugin incorrectly
assumed that all strings provided by browser are NUL terminated, which
is not guaranteed by the NPAPI (Netscape Plugin Application
Programming Interface). When used in a browser that does not NUL
terminate NPVariant NPStrings, this could lead to buffer over-read or
over-write, resulting in possible information leak, crash, or code
execution.

Mozilla browsers currently NUL terminate strings, however recent
Chrome versions are known not to provide NUL terminated data."
  );
  # http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2012-July/019580.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f9c1f1b"
  );
  # http://www.freebsd.org/ports/portaudit/55b498e2-e56c-11e1-bbd5-001c25e46b1d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39080327"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/14");
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

if (pkg_test(save_report:TRUE, pkg:"icedtea-web<1.2.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
