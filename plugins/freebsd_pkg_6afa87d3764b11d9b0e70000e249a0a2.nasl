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
  script_id(18972);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/21 23:57:17 $");

  script_cve_id("CVE-2005-0089");

  script_name(english:"FreeBSD : python -- SimpleXMLRPCServer.py allows unrestricted traversal (6afa87d3-764b-11d9-b0e7-0000e249a0a2)");
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
"According to Python Security Advisory PSF-2005-001,

The Python development team has discovered a flaw in the
SimpleXMLRPCServer library module which can give remote attackers
access to internals of the registered object or its module or possibly
other modules. The flaw only affects Python XML-RPC servers that use
the register_instance() method to register an object without a
_dispatch() method. Servers using only register_function() are not
affected.

On vulnerable XML-RPC servers, a remote attacker may be able to view
or modify globals of the module(s) containing the registered
instance's class(es), potentially leading to data loss or arbitrary
code execution. If the registered object is a module, the danger is
particularly serious. For example, if the registered module imports
the os module, an attacker could invoke the os.system() function.

Note: This vulnerability affects your system only if you're running
SimpleXMLRPCServer-based server. This isn't harmful at all if you
don't run any internet server written in Python or your server doesn't
serve in XML-RPC protocol."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.python.org/security/PSF-2005-001/"
  );
  # http://www.freebsd.org/ports/portaudit/6afa87d3-764b-11d9-b0e7-0000e249a0a2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07577ee5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python+ipv6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"python>=2.2<2.2.3_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python>=2.3<2.3.4_4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python>=2.4<2.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python>=2.5.a0.20050129<2.5.a0.20050129_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python+ipv6>=2.2<2.2.3_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python+ipv6>=2.3<2.3.4_4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python+ipv6>=2.4<2.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python+ipv6>=2.5.a0.20050129<2.5.a0.20050129_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
