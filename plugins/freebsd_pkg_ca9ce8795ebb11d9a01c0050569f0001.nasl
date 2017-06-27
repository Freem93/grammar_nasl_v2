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
  script_id(19118);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2005-0021", "CVE-2005-0022");
  script_bugtraq_id(12185, 12188, 12268);

  script_name(english:"FreeBSD : exim -- two buffer overflow vulnerabilities (ca9ce879-5ebb-11d9-a01c-0050569f0001)");
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
"1. The function host_aton() can overflow a buffer if it is presented
with an illegal IPv6 address that has more than 8 components.

2. The second report described a buffer overflow in the function
spa_base64_to_bits(), which is part of the code for SPA
authentication."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.exim.org/mail-archives/exim-announce/2005/msg00000.html"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110573573800377
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110573573800377"
  );
  # http://www.freebsd.org/ports/portaudit/ca9ce879-5ebb-11d9-a01c-0050569f0001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdbdb4e3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exim-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exim-ldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exim-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exim-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:exim-sa-exim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"exim<4.43+28_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"exim-ldap<4.43+28_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"exim-ldap2<4.43+28_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"exim-mysql<4.43+28_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"exim-postgresql<4.43+28_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"exim-sa-exim<4.43+28_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
