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
  script_id(96620);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/19 15:37:19 $");

  script_cve_id("CVE-2016-2120", "CVE-2016-7068", "CVE-2016-7072", "CVE-2016-7073", "CVE-2016-7074");

  script_name(english:"FreeBSD : powerdns -- multiple vulnerabilities (e3200958-dd6c-11e6-ae1b-002590263bf5)");
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
"PowerDNS reports :

2016-02: Crafted queries can cause abnormal CPU usage

2016-03: Denial of service via the web server

2016-04: Insufficient validation of TSIG signatures

2016-05: Crafted zone record can cause a denial of service"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=216135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=216136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-02/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-03/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-04/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-05/"
  );
  # https://blog.powerdns.com/2017/01/13/powerdns-authoritative-server-4-0-2-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58ab7632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blog.powerdns.com/2017/01/13/powerdns-recursor-4-0-4-released/"
  );
  # http://www.freebsd.org/ports/portaudit/e3200958-dd6c-11e6-ae1b-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0696d78"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:powerdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:powerdns-recursor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");
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

if (pkg_test(save_report:TRUE, pkg:"powerdns<3.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"powerdns>=4.0.0<4.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"powerdns-recursor<3.7.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"powerdns-recursor>=4.0.0<4.0.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
