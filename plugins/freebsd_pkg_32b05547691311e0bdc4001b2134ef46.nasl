#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(53468);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/06/23 10:44:40 $");

  script_cve_id("CVE-2011-0611");

  script_name(english:"FreeBSD : linux-flashplugin -- remote code execution vulnerability (32b05547-6913-11e0-bdc4-001b2134ef46)");
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
"Adobe Product Security Incident Response Team reports :

A critical vulnerability exists in Flash Player 10.2.153.1 and earlier
versions (Adobe Flash Player 10.2.154.25 and earlier for Chrome users)
for Windows, Macintosh, Linux and Solaris, Adobe Flash Player
10.2.156.12 and earlier versions for Android, and the Authplay.dll
component that ships with Adobe Reader and Acrobat X (10.0.2) and
earlier 10.x and 9.x versions for Windows and Macintosh operating
systems.

This vulnerability (CVE-2011-0611) could cause a crash and potentially
allow an attacker to take control of the affected system. There are
reports that this vulnerability is being exploited in the wild in
targeted attacks via a malicious Web page or a Flash (.swf) file
embedded in a Microsoft Word (.doc) or Microsoft Excel (.xls) file
delivered as an email attachment, targeting the Windows platform. At
this time, Adobe is not aware of any attacks via PDF targeting Adobe
Reader and Acrobat. Adobe Reader X Protected Mode mitigations would
prevent an exploit of this kind from executing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa11-02.html"
  );
  # http://www.freebsd.org/ports/portaudit/32b05547-6913-11e0-bdc4-001b2134ef46.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41131039"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-flashplugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"linux-flashplugin<=9.0r289")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-flashplugin<10.2r159.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
