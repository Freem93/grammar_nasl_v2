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
  script_id(21527);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/08/09 10:50:39 $");

  script_cve_id("CVE-2005-2498");

  script_name(english:"FreeBSD : pear-XML_RPC -- remote PHP code injection vulnerability (e65ad1bf-0d8b-11da-90d0-00304823c0d3)");
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
"A Hardened-PHP Project Security Advisory reports :

When the library parses XMLRPC requests/responses, it constructs a
string of PHP code, that is later evaluated. This means any failure to
properly handle the construction of this string can result in
arbitrary execution of PHP code.

This new injection vulnerability is cause by not properly handling the
situation, when certain XML tags are nested in the parsed document,
that were never meant to be nested at all. This can be easily
exploited in a way, that user-input is placed outside of string
delimiters within the evaluation string, which obviously results in
arbitrary code execution.

Note that several applications contains an embedded version on
XML_RPC, therefor making them the vulnerable to the same code
injection vulnerability."
  );
  # http://b2evolution.net/news/2005/08/31/fix_for_xml_rpc_vulnerability_again_1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c00f82b"
  );
  # http://downloads.phpgroupware.org/changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e38c06a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/files/sa-2005-004/advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/project/shownotes.php?release_id=349626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_142005.66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_152005.67.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyfaq.de/advisory_2005-08-15.php"
  );
  # http://www.freebsd.org/ports/portaudit/e65ad1bf-0d8b-11da-90d0-00304823c0d3.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a14b4779"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:b2evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drupal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:eGroupWare");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pear-XML_RPC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpAdsNew");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyfaq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"pear-XML_RPC<1.4.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpmyfaq<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drupal<4.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"eGroupWare<1.0.0.009")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpAdsNew<2.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpgroupware<0.9.16.007")) flag++;
if (pkg_test(save_report:TRUE, pkg:"b2evolution<0.9.0.12_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
