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
  script_id(92832);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/04/25 13:23:28 $");

  script_cve_id("CVE-2016-6170", "CVE-2016-6171", "CVE-2016-6172", "CVE-2016-6173");

  script_name(english:"FreeBSD : BIND,Knot,NSD,PowerDNS -- denial over service via oversized zone transfers (7d08e608-5e95-11e6-b334-002590263bf5)");
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

DNS protocols were designed with the assumption that a certain amount
of trust could be presumed between the operators of primary and
secondary servers for a given zone. However, in current practice some
organizations have scenarios which require them to accept zone data
from sources that are not fully trusted (for example: providers of
secondary name service). A party who is allowed to feed data into a
zone (e.g. by AXFR, IXFR, or Dynamic DNS updates) can overwhelm the
server which is accepting data by intentionally or accidentally
exhausting that server's memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-01390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2016/07/06/4"
  );
  # http://www.freebsd.org/ports/portaudit/7d08e608-5e95-11e6-b334-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a7a1ae0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind910");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind911");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:knot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:knot1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:knot2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:powerdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bind99<=9.9.9P2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind910<=9.10.4P2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind911<=9.11.0.b2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind9-devel<=9.12.0.a.2016.11.02")) flag++;
if (pkg_test(save_report:TRUE, pkg:"knot<1.6.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"knot1<1.6.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"knot2<2.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nsd<4.1.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"powerdns<4.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
