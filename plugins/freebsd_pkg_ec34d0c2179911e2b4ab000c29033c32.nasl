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
  script_id(62571);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/15 19:22:34 $");

  script_cve_id("CVE-2012-3363");
  script_xref(name:"Secunia", value:"49665");

  script_name(english:"FreeBSD : Zend Framework -- Multiple vulnerabilities via XXE injection (ec34d0c2-1799-11e2-b4ab-000c29033c32)");
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
"The Zend Framework team reports :

The XmlRpc package of Zend Framework is vulnerable to XML eXternal
Entity Injection attacks (both server and client). The
SimpleXMLElement class (SimpleXML PHP extension) is used in an
insecure way to parse XML data. External entities can be specified by
adding a specific DOCTYPE element to XML-RPC requests. By exploiting
this vulnerability an application may be coerced to open arbitrary
files and/or TCP connections.

Additionally, the Zend_Dom, Zend_Feed, Zend_Soap, and Zend_XmlRpc
components are vulnerable to XML Entity Expansion (XEE) vectors,
leading to Denial of Service vectors. XEE attacks occur when the XML
DOCTYPE declaration includes XML entity definitions that contain
either recursive or circular references; this leads to CPU and memory
consumption, making Denial of Service exploits trivial to implement."
  );
  # https://www.sec-consult.com/files/20120626-0_zend_framework_xxe_injection.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8588fbd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://framework.zend.com/security/advisory/ZF2012-01"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://framework.zend.com/security/advisory/ZF2012-02"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2012/06/26/2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.magentocommerce.com/download/release_notes"
  );
  # http://www.freebsd.org/ports/portaudit/ec34d0c2-1799-11e2-b4ab-000c29033c32.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e26f5b43"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ZendFramework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:magento");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"ZendFramework<1.11.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"magento<1.7.0.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");