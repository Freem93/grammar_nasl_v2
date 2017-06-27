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
  script_id(19084);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/13 14:37:09 $");

  script_cve_id("CVE-2005-0941");
  script_bugtraq_id(13092);

  script_name(english:"FreeBSD : openoffice -- DOC document heap overflow vulnerability (b206dd82-ac67-11d9-a788-0001020eed82)");
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
"AD-LAB reports that a heap-based buffer overflow vulnerability exists
in OpenOffice's handling of DOC documents. When reading a DOC document
16 bit from a 32 bit integer is used for memory allocation, but the
full 32 bit is used for further processing of the document. This can
allow an attacker to crash OpenOffice, or potentially execute
arbitrary code as the user running OpenOffice, by tricking an user
into opening a specially crafted DOC document."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=111325305109137
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=111325305109137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/issues/show_bug.cgi?id=46388"
  );
  # http://www.freebsd.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?429f5d41"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jp-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ko-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kr-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nl-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pl-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pt-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pt_BR-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:se-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sk-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sl-openoffice-SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sl-openoffice-SL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tr-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-openoffice-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-openoffice-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh_TW-openoffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ar-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ar-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ca-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ca-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"cs-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"cs-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dk-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dk-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"el-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"el-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"es-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"es-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"et-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"et-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fi-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fi-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gr-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gr-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"hu-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"hu-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"it-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"it-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nl-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nl-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pl-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pl-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt_BR-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt_BR-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"se-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"se-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sk-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sk-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sl-openoffice-SI<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sl-openoffice-SI>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tr-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tr-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-CN<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-CN>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-TW<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice-TW>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jp-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jp-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kr-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kr-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sl-openoffice-SL<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sl-openoffice-SL>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh_TW-openoffice<1.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh_TW-openoffice>2.*<=2.0.20050406")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice>=6.0.a609<=6.0.a638")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice>=641c<=645")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice=1.1RC4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice=1.1rc5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice>=6.0.a609<=6.0.a638")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice>=641c<=645")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice=1.1RC4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-openoffice=1.1rc5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
