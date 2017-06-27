#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
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
  script_id(99325);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/04/24 13:52:13 $");

  script_cve_id("CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138");
  script_xref(name:"IAVA", value:"2017-A-0120");

  script_name(english:"FreeBSD : BIND -- multiple vulnerabilities (c6861494-1ffb-11e7-934d-d05099c0ae8c)");
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
"ISC reports :

A query with a specific set of characteristics could cause a server
using DNS64 to encounter an assertion failure and terminate.

An attacker could deliberately construct a query, enabling
denial-of-service against a server if it was configured to use the
DNS64 feature and other preconditions were met.

Mistaken assumptions about the ordering of records in the answer
section of a response containing CNAME or DNAME resource records could
lead to a situation in which named would exit with an assertion
failure when processing a response in which records occurred in an
unusual order.

named contains a feature which allows operators to issue commands to a
running server by communicating with the server process over a control
channel, using a utility program such as rndc.

A regression introduced in a recent feature change has created a
situation under which some versions of named can be caused to exit
with a REQUIRE assertion failure if they are sent a null command
string."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-01465/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-01466/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-01471/0"
  );
  # http://www.freebsd.org/ports/portaudit/c6861494-1ffb-11e7-934d-d05099c0ae8c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f60e0e7c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind910");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind911");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bind99<9.9.9P8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind910<9.10.4P8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind911<9.11.0P5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind9-devel<=9.12.0.a.2017.03.25")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
