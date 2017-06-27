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
  script_id(88875);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/19 14:02:53 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-8157", "CVE-2014-8158", "CVE-2014-9029", "CVE-2016-2089");

  script_name(english:"FreeBSD : jasper -- multiple vulnerabilities (006e3b7c-d7d7-11e5-b85f-0018fe623f2b)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"oCERT reports :

The library is affected by a double-free vulnerability in function
jas_iccattrval_destroy() as well as a heap-based buffer overflow in
function jp2_decode(). A specially crafted jp2 file can be used to
trigger the vulnerabilities.

oCERT reports :

The library is affected by an off-by-one error in a buffer boundary
check in jpc_dec_process_sot(), leading to a heap based buffer
overflow, as well as multiple unrestricted stack memory use issues in
jpc_qmfb.c, leading to stack overflow. A specially crafted jp2 file
can be used to trigger the vulnerabilities.

oCERT reports :

Multiple off-by-one flaws, leading to heap-based buffer overflows,
were found in the way JasPer decoded JPEG 2000 files. A specially
crafted file could cause an application using JasPer to crash or,
possibly, execute arbitrary code.

limingxing reports :

A vulnerability was found in the way the JasPer's jas_matrix_clip()
function parses certain JPEG 2000 image files. A specially crafted
file could cause an application using JasPer to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ocert.org/advisories/ocert-2014-012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1173157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1173162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ocert.org/advisories/ocert-2015-001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1179282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ocert.org/advisories/ocert-2014-009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1167537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2016/q1/233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302636"
  );
  # http://www.freebsd.org/ports/portaudit/006e3b7c-d7d7-11e5-b85f-0018fe623f2b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78a7882f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jasper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"jasper<1.900.1_16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
