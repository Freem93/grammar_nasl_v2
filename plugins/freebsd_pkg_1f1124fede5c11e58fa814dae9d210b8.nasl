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
  script_id(89006);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/03/20 13:44:32 $");

  script_cve_id("CVE-2015-5345", "CVE-2015-5346", "CVE-2016-0706", "CVE-2016-0714");

  script_name(english:"FreeBSD : tomcat -- multiple vulnerabilities (1f1124fe-de5c-11e5-8fa8-14dae9d210b8)");
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
"Mark Thomas reports :

- CVE-2015-5345 Apache Tomcat Directory disclosure

- CVE-2016-0706 Apache Tomcat Security Manager bypass

- CVE-2016-0714 Apache Tomcat Security Manager Bypass"
  );
  # http://mail-archives.apache.org/mod_mbox/www-announce/201602.mbox/%3c56CAEF96.7070701@apache.org%3e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?110db969"
  );
  # http://mail-archives.apache.org/mod_mbox/www-announce/201602.mbox/%3c56CAEF6A.70703@apache.org%3e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2344e1ab"
  );
  # http://mail-archives.apache.org/mod_mbox/www-announce/201602.mbox/%3c56CAEF4F.5090003@apache.org%3e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7476e921"
  );
  # http://www.freebsd.org/ports/portaudit/1f1124fe-de5c-11e5-8fa8-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bb96890"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tomcat8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
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

if (pkg_test(save_report:TRUE, pkg:"tomcat<6.0.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tomcat7<7.0.68")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tomcat8<8.0.30")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
