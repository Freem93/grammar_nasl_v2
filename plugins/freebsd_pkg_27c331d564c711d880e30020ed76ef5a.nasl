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
  script_id(37542);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/08/09 10:50:38 $");

  script_cve_id("CVE-2004-0097");
  script_xref(name:"CERT-CC", value:"CA-2004-01");
  script_xref(name:"CERT", value:"749342");

  script_name(english:"FreeBSD : Vulnerabilities in H.323 implementations (27c331d5-64c7-11d8-80e3-0020ed76ef5a)");
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
"The NISCC and the OUSPG developed a test suite for the H.323 protocol.
This test suite has uncovered vulnerabilities in several H.323
implementations with impacts ranging from denial-of-service to
arbitrary code execution.

In the FreeBSD Ports Collection, `pwlib' is directly affected. Other
applications such as `asterisk' and `openh323' incorporate `pwlib'
statically and so are also independently affected."
  );
  # http://www.uniras.gov.uk/vuls/2004/006489/h323.htm
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc7c4598"
  );
  # http://www.ee.oulu.fi/research/ouspg/protos/testing/c07/h2250v4/index.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab015474"
  );
  # http://www.southeren.com/blog/archives/000055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bec8a8df"
  );
  # http://www.freebsd.org/ports/portaudit/27c331d5-64c7-11d8-80e3-0020ed76ef5a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf6f3b4a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pwlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/22");
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

if (pkg_test(save_report:TRUE, pkg:"pwlib<1.5.0_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"asterisk<=0.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openh323<1.12.0_4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
