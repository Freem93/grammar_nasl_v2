#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(19159);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/08/13 14:23:43 $");

  script_cve_id("CVE-2004-0595");
  script_bugtraq_id(10724);

  script_name(english:"FreeBSD : php -- strip_tags XSS vulnerability (edf61c61-0f07-11d9-8393-000103ccf9d6)");
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
"Stefan Esser of e-matters discovered that PHP's strip_tags() function
would ignore certain characters during parsing of tags, allowing these
tags to pass through. Select browsers could then parse these tags,
possibly allowing cross-site scripting attacks."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=108981589117423
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=108981589117423"
  );
  # http://security.e-matters.de/advisories/122004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d4bce03"
  );
  # http://www.freebsd.org/ports/portaudit/edf61c61-0f07-11d9-8393-000103ccf9d6.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0090f36"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php4-twig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-dtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-nms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-cli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"mod_php4-twig<=4.3.7_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4<=4.3.7_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cgi<=4.3.7_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cli<=4.3.7_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-dtc<=4.3.7_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-horde<=4.3.7_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-nms<=4.3.7_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php4<=4.3.7_3,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5<=5.0.0.r3_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cgi<=5.0.0.r3_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cli<=5.0.0.r3_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php5<=5.0.0.r3_2,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
