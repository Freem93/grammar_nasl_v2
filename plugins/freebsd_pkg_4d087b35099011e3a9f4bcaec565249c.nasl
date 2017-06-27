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
  script_id(69412);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/08/21 12:19:10 $");

  script_cve_id("CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3895", "CVE-2011-3929", "CVE-2011-3936", "CVE-2011-3937", "CVE-2011-3940", "CVE-2011-3945", "CVE-2011-3947", "CVE-2011-3951", "CVE-2011-3952", "CVE-2011-4031", "CVE-2011-4351", "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2011-4579", "CVE-2012-0848", "CVE-2012-0850", "CVE-2012-0851", "CVE-2012-0852", "CVE-2012-0853", "CVE-2012-0858", "CVE-2012-0947", "CVE-2012-2772", "CVE-2012-2775", "CVE-2012-2777", "CVE-2012-2779", "CVE-2012-2783", "CVE-2012-2784", "CVE-2012-2786", "CVE-2012-2787", "CVE-2012-2788", "CVE-2012-2790", "CVE-2012-2791", "CVE-2012-2793", "CVE-2012-2794", "CVE-2012-2798", "CVE-2012-2800", "CVE-2012-2801", "CVE-2012-2803", "CVE-2012-5144");

  script_name(english:"FreeBSD : gstreamer-ffmpeg -- Multiple vulnerabilities in bundled libav (4d087b35-0990-11e3-a9f4-bcaec565249c)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bundled version of libav in gstreamer-ffmpeg contains a number of
vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://libav.org/releases/libav-0.7.7.changelog"
  );
  # http://www.freebsd.org/ports/portaudit/4d087b35-0990-11e3-a9f4-bcaec565249c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0ad15d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gstreamer-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");
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

if (pkg_test(save_report:TRUE, pkg:"gstreamer-ffmpeg<0.10.13_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
