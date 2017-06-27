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

include("compat.inc");

if (description)
{
  script_id(36897);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/14 18:38:13 $");

  script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");
  script_osvdb_id(8312, 8313, 8314, 8315, 8316);
  script_xref(name:"CERT", value:"160448");
  script_xref(name:"CERT", value:"236656");
  script_xref(name:"CERT", value:"286464");
  script_xref(name:"CERT", value:"388984");
  script_xref(name:"CERT", value:"477512");
  script_xref(name:"CERT", value:"817368");
  script_xref(name:"Secunia", value:"12219");
  script_xref(name:"Secunia", value:"12232");

  script_name(english:"FreeBSD : libpng stack-based buffer overflow and other code concerns (f9e3e60b-e650-11d8-9b0a-000347a4fa7d)");
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
"Chris Evans has discovered multiple vulnerabilities in libpng, which
can be exploited by malicious people to compromise a vulnerable system
or cause a DoS (Denial of Service)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/370853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://scary.beasts.org/security/CESA-2004-001.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=251381"
  );
  # http://www.uscert.gov/cas/techalerts/TA04-217A.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0481eb4e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dl.sourceforge.net/sourceforge/libpng/ADVISORY.txt"
  );
  # http://www.freebsd.org/ports/portaudit/f9e3e60b-e650-11d8-9b0a-000347a4fa7d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfe92729"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-netscape-communicator-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-netscape-navigator-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ko-netscape-communicator-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ko-netscape-navigator-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-netscape-communicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-netscape-navigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-png");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-gtk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:netscape-communicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:netscape-navigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:png");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pt_BR-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"png<=1.2.5_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-png<=1.0.14_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-png>=1.2<=1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox<0.9.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<0.7.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla<1.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla-devel<1.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla<1.7.2,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla>=1.8.a,2<=1.8.a2,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-gtk1<1.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"netscape-communicator<=4.78")) flag++;
if (pkg_test(save_report:TRUE, pkg:"netscape-navigator<=4.78")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-netscape-communicator<=4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-netscape-navigator<=4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-netscape-navigator-linux<=4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-netscape-communicator-linux<=4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-netscape-communicator-linux<=4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-netscape-navigator-linux<=4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"netscape7<=7.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-netscape7<=7.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt_BR-netscape7<=7.02")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-netscape7<=7.02")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-netscape7<=7.02")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
