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
  script_id(66837);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/08/03 02:36:00 $");

  script_cve_id("CVE-2013-3919");

  script_name(english:"FreeBSD : dns/bind9* -- A recursive resolver can be crashed by a query for a malformed zone (72f35727-ce83-11e2-be04-005056a37f68)");
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

A bug has been discovered in the most recent releases of BIND 9 which
has the potential for deliberate exploitation as a denial-of-service
attack. By sending a recursive resolver a query for a record in a
specially malformed zone, an attacker can cause BIND 9 to exit with a
fatal 'RUNTIME_CHECK' error in resolver.c."
  );
  # http://www.freebsd.org/ports/portaudit/72f35727-ce83-11e2-be04-005056a37f68.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2de2572f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind96-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind98");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind98-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bind99>9.9.3<9.9.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind99-base>9.9.3<9.9.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind98>9.8.5<9.8.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind98-base>9.8.5<9.8.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind96>9.6.3.1.ESV.R9<9.6.3.2.ESV.R9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind96-base>9.6.3.1.ESV.R9<9.6.3.2.ESV.R9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
