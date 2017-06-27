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
  script_id(86879);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/21 14:44:24 $");

  script_name(english:"FreeBSD : moodle -- multiple vulnerabilities (82b3ca2a-8c07-11e5-bd18-002590263bf5)");
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
"Moodle Release Notes report :

MSA-15-0037 Possible to send a message to a user who blocked messages
from non contacts

MSA-15-0038 DDoS possibility in Atto

MSA-15-0039 CSRF in site registration form

MSA-15-0040 Student XSS in survey

MSA-15-0041 XSS in flash video player

MSA-15-0042 CSRF in lesson login form

MSA-15-0043 Web service core_enrol_get_enrolled_users does not respect
course group mode

MSA-15-0044 Capability to view available badges is not respected

MSA-15-0045 SCORM module allows to bypass access restrictions based on
date

MSA-15-0046 Choice module closing date can be bypassed"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.moodle.org/dev/Moodle_2.7.11_release_notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.moodle.org/dev/Moodle_2.8.9_release_notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.moodle.org/dev/Moodle_2.9.3_release_notes"
  );
  # http://www.freebsd.org/ports/portaudit/82b3ca2a-8c07-11e5-bd18-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1de1405a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:moodle27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:moodle28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:moodle29");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"moodle27<2.7.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"moodle28<2.8.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"moodle29<2.9.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
