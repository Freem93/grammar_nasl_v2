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
  script_id(18852);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/05/13 14:37:08 $");

  script_cve_id("CVE-2005-1080");
  script_xref(name:"Secunia", value:"14902");

  script_name(english:"FreeBSD : jdk -- jar directory traversal vulnerability (18e5428f-ae7c-11d9-837d-000e0c2e438a)");
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
"Pluf has discovered a vulnerability in Sun Java JDK/SDK, which
potentially can be exploited by malicious people to compromise a
user's system.

The jar tool does not check properly if the files to be extracted have
the string '../' on its names, so it's possible for an attacker to
create a malicious jar file in order to overwrite arbitrary files
within the filesystem."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=111331593310508
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=111331593310508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securiteam.com/securitynews/5IP0C0AFGW.html"
  );
  # http://www.freebsd.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba58c0cf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:diablo-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:diablo-jdk-freebsd6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-blackdown-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-ibm-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-sun-jdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"jdk<=1.2.2p11_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jdk>=1.3.*<=1.3.1p9_4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jdk>=1.4.*<=1.4.2p7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jdk>=1.5.*<=1.5.0p1_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-ibm-jdk<=1.4.2_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jdk<=1.4.2.08_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jdk=1.5.0b1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jdk=1.5.0b1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jdk>=1.5.0,2<=1.5.0.02,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-blackdown-jdk<=1.4.2_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"diablo-jdk<=1.3.1.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"diablo-jdk-freebsd6<=i386.1.5.0.07.00")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-jdk>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
