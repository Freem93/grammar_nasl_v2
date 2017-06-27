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
  script_id(44390);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/22 00:10:42 $");

  script_name(english:"FreeBSD : apache -- Prevent chunk-size integer overflow on platforms where sizeof(int) < sizeof(long) (cae01d7b-110d-11df-955a-00219b0fc4d8)");
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
"Apache ChangeLog reports :

Integer overflow in the ap_proxy_send_fb function in
proxy/proxy_util.c in mod_proxy in the Apache HTTP Server before
1.3.42 on 64-bit platforms allows remote origin servers to cause a
denial of service (daemon crash) or possibly execute arbitrary code
via a large chunk size that triggers a heap-based buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-0010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.security-database.com/detail.php?alert=CVE-2010-0010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security-tracker.debian.org/tracker/CVE-2010-0010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vupen.com/english/Reference-CVE-2010-0010.php"
  );
  # http://www.freebsd.org/ports/portaudit/cae01d7b-110d-11df-955a-00219b0fc4d8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6f68bf7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache_fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-apache+mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"apache<1.3.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_perl<1.3.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+ipv6<1.3.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache_fp>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-apache<1.3.42+30.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-apache+mod_ssl<1.3.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+ssl<1.3.42.1.57_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+ipv6<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+ipv6<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+mod_deflate<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_deflate<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_deflate+ipv6<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_deflate<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6<1.3.41+2.8.27_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6<1.3.41+2.8.27_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
