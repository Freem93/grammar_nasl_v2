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
  script_id(57926);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/08/09 10:50:39 $");

  script_cve_id("CVE-2012-0845");

  script_name(english:"FreeBSD : Python -- DoS via malformed XML-RPC / HTTP POST request (b4f8be9e-56b2-11e1-9fb7-003067b2972c)");
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
"Jan Lieskovsky reports,

A denial of service flaw was found in the way Simple XML-RPC Server
module of Python processed client connections, that were closed prior
the complete request body has been received. A remote attacker could
use this flaw to cause Python Simple XML-RPC based server process to
consume excessive amount of CPU."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.python.org/issue14001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=789790"
  );
  # https://bugs.pypy.org/issue1047
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.archive.org/liveweb/https://bugs.pypy.org/issue1047"
  );
  # http://www.freebsd.org/ports/portaudit/b4f8be9e-56b2-11e1-9fb7-003067b2972c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9ef7bfc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pypy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python32");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");
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

if (pkg_test(save_report:TRUE, pkg:"python32<=3.2.2_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python31<=3.1.4_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python27<=2.7.2_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python26<=2.6.7_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python25<=2.5.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python24<=2.4.5_8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pypy<=1.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
