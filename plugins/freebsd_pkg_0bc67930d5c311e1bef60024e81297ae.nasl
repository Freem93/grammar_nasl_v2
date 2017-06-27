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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60114);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/21 23:43:35 $");

  script_cve_id("CVE-2012-3817");

  script_name(english:"FreeBSD : dns/bind9* -- Heavy DNSSEC Validation Load Can Cause a 'Bad Cache' Assertion Failure (0bc67930-d5c3-11e1-bef6-0024e81297ae)");
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

High numbers of queries with DNSSEC validation enabled can cause an
assertion failure in named, caused by using a 'bad cache' data
structure before it has been initialized.

BIND 9 stores a cache of query names that are known to be failing due
to misconfigured name servers or a broken chain of trust. Under high
query loads when DNSSEC validation is active, it is possible for a
condition to arise in which data from this cache of failing queries
could be used before it was fully initialized, triggering an assertion
failure.

This bug cannot be encountered unless your server is doing DNSSEC
validation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-00729"
  );
  # http://www.freebsd.org/ports/portaudit/0bc67930-d5c3-11e1-bef6-0024e81297ae.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1758db5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind98");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/25");
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

if (pkg_test(save_report:TRUE, pkg:"bind99<9.9.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind98<9.8.3.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind97<9.7.6.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind96<9.6.3.1.ESV.R7.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
