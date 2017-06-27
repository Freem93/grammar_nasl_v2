#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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
  script_id(87982);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/01/20 16:28:29 $");

  script_cve_id("CVE-2012-4504");

  script_name(english:"FreeBSD : libproxy -- stack-based buffer overflow (3b5c2362-bd07-11e5-b7ef-5453ed2e2b49)");
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
"Tomas Hoger reports :

A buffer overflow flaw was discovered in the libproxy's url::get_pac()
used to download proxy.pac proxy auto-configuration file. A malicious
host hosting proxy.pac, or a man in the middle attacker, could use
this flaw to trigger a stack-based buffer overflow in an application
using libproxy, if proxy configuration instructed it to download
proxy.pac file from a remote HTTP server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-4504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2012/10/12/1"
  );
  # https://github.com/libproxy/libproxy/commit/c440553c12836664afd24a24fb3a4d10a2facd2c
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef5c1679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=864417"
  );
  # https://groups.google.com/forum/?fromgroups=#!topic/libproxy/VxZ8No7mT0E
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3e8a475"
  );
  # http://www.freebsd.org/ports/portaudit/3b5c2362-bd07-11e5-b7ef-5453ed2e2b49.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e439340a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libproxy-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libproxy-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libproxy-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libproxy-webkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"libproxy>=0.4.0<0.4.6_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libproxy-gnome>=0.4.0<0.4.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libproxy-kde>=0.4.0<0.4.6_6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libproxy-perl>=0.4.0<0.4.6_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libproxy-webkit>=0.4.0<0.4.6_4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
