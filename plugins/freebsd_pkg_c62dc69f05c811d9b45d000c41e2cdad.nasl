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
  script_id(36459);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/22 00:10:42 $");

  script_cve_id("CVE-2004-0752");

  script_name(english:"FreeBSD : openoffice -- document disclosure (c62dc69f-05c8-11d9-b45d-000c41e2cdad)");
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
"OpenOffice creates a working directory in /tmp on startup, and uses
this directory to temporarily store document content. However, the
permissions of the created directory may allow other user on the
system to read these files, potentially exposing information the user
likely assumed was inaccessible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/issues/show_bug.cgi?id=33357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://securitytracker.com/alerts/2004/Sep/1011205.html"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=109483308421566
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=109483308421566"
  );
  # http://www.freebsd.org/ports/portaudit/c62dc69f-05c8-11d9-b45d-000c41e2cdad.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?690f4d44"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ar-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ca-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cs-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dk-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:el-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:es-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:et-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fi-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gr-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:hu-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:it-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ko-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nl-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pl-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pt-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pt_BR-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:se-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sk-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sl-openoffice-SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tr-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-openoffice-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-openoffice-TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ar-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ar-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ca-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ca-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"cs-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"cs-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dk-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dk-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"el-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"el-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"es-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"es-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"et-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"et-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fi-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fi-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gr-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gr-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"hu-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"hu-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"it-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"it-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nl-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nl-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pl-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pl-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt_BR-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt_BR-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"se-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"se-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sk-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sk-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sl-openoffice-SI<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sl-openoffice-SI>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tr-openoffice<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tr-openoffice>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-CN<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-CN>=2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-TW<1.1.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-TW>=2.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
