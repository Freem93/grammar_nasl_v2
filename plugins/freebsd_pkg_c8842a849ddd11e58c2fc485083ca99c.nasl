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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87270);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/01/10 05:42:14 $");

  script_cve_id("CVE-2015-8045", "CVE-2015-8047", "CVE-2015-8048", "CVE-2015-8049", "CVE-2015-8050", "CVE-2015-8051", "CVE-2015-8052", "CVE-2015-8053", "CVE-2015-8054", "CVE-2015-8055", "CVE-2015-8056", "CVE-2015-8057", "CVE-2015-8058", "CVE-2015-8059", "CVE-2015-8060", "CVE-2015-8061", "CVE-2015-8062", "CVE-2015-8063", "CVE-2015-8064", "CVE-2015-8065", "CVE-2015-8066", "CVE-2015-8067", "CVE-2015-8068", "CVE-2015-8069", "CVE-2015-8070", "CVE-2015-8071", "CVE-2015-8401", "CVE-2015-8402", "CVE-2015-8403", "CVE-2015-8404", "CVE-2015-8405", "CVE-2015-8406", "CVE-2015-8407", "CVE-2015-8408", "CVE-2015-8409", "CVE-2015-8410", "CVE-2015-8411", "CVE-2015-8412", "CVE-2015-8413", "CVE-2015-8414", "CVE-2015-8415", "CVE-2015-8416", "CVE-2015-8417", "CVE-2015-8419", "CVE-2015-8420", "CVE-2015-8421", "CVE-2015-8422", "CVE-2015-8423", "CVE-2015-8424", "CVE-2015-8425", "CVE-2015-8426", "CVE-2015-8427", "CVE-2015-8428", "CVE-2015-8429", "CVE-2015-8430", "CVE-2015-8431", "CVE-2015-8432", "CVE-2015-8433", "CVE-2015-8434", "CVE-2015-8435", "CVE-2015-8436", "CVE-2015-8437", "CVE-2015-8438", "CVE-2015-8439", "CVE-2015-8440", "CVE-2015-8441", "CVE-2015-8442", "CVE-2015-8443", "CVE-2015-8444", "CVE-2015-8445", "CVE-2015-8446", "CVE-2015-8447", "CVE-2015-8448", "CVE-2015-8449", "CVE-2015-8450", "CVE-2015-8451", "CVE-2015-8452", "CVE-2015-8453");

  script_name(english:"FreeBSD : flash -- multiple vulnabilities (c8842a84-9ddd-11e5-8c2f-c485083ca99c)");
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
"Adobe reports :

These updates resolve heap buffer overflow vulnerabilities that could
lead to code execution (CVE-2015-8438, CVE-2015-8446).

These updates resolve memory corruption vulnerabilities that could
lead to code execution (CVE-2015-8444, CVE-2015-8443, CVE-2015-8417,
CVE-2015-8416, CVE-2015-8451, CVE-2015-8047, CVE-2015-8053,
CVE-2015-8045, CVE-2015-8051, CVE-2015-8060, CVE-2015-8419,
CVE-2015-8408).

These updates resolve security bypass vulnerabilities (CVE-2015-8453,
CVE-2015-8440, CVE-2015-8409).

These updates resolve a stack overflow vulnerability that could lead
to code execution (CVE-2015-8407).

These updates resolve a type confusion vulnerability that could lead
to code execution (CVE-2015-8439).

These updates resolve an integer overflow vulnerability that could
lead to code execution (CVE-2015-8445).

These updates resolve a buffer overflow vulnerability that could lead
to code execution (CVE-2015-8415).

These updates resolve use-after-free vulnerabilities that could lead
to code execution (CVE-2015-8050, CVE-2015-8049, CVE-2015-8437,
CVE-2015-8450, CVE-2015-8449, CVE-2015-8448, CVE-2015-8436,
CVE-2015-8452, CVE-2015-8048, CVE-2015-8413, CVE-2015-8412,
CVE-2015-8410, CVE-2015-8411, CVE-2015-8424, CVE-2015-8422,
CVE-2015-8420, CVE-2015-8421, CVE-2015-8423, CVE-2015-8425,
CVE-2015-8433, CVE-2015-8432, CVE-2015-8431, CVE-2015-8426,
CVE-2015-8430, CVE-2015-8427, CVE-2015-8428, CVE-2015-8429,
CVE-2015-8434, CVE-2015-8435, CVE-2015-8414, CVE-2015-8052,
CVE-2015-8059, CVE-2015-8058, CVE-2015-8055, CVE-2015-8057,
CVE-2015-8056, CVE-2015-8061, CVE-2015-8067, CVE-2015-8066,
CVE-2015-8062, CVE-2015-8068, CVE-2015-8064, CVE-2015-8065,
CVE-2015-8063, CVE-2015-8405, CVE-2015-8404, CVE-2015-8402,
CVE-2015-8403, CVE-2015-8071, CVE-2015-8401, CVE-2015-8406,
CVE-2015-8069, CVE-2015-8070, CVE-2015-8441, CVE-2015-8442,
CVE-2015-8447)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html"
  );
  # http://www.freebsd.org/ports/portaudit/c8842a84-9ddd-11e5-8c2f-c485083ca99c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6612cc56"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6_64-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-flashplugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"linux-c6-flashplugin<11.2r202.554")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-flashplugin<11.2r202.554")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6_64-flashplugin<11.2r202.554")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
