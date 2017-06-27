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
  script_id(22105);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/05/13 14:37:10 $");

  script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (e2a92664-1d60-11db-88cf-000c6ec775d9)");
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
"A Mozilla Foundation Security Advisory reports of multiple issues.
Several of which can be used to run arbitrary code with the privilege
of the user running the program.

- MFSA 2006-56 chrome: scheme loading remote content

- MFSA 2006-55 Crashes with evidence of memory corruption (rv:1.8.0.5)

- MFSA 2006-54 XSS with XPCNativeWrapper(window).Function(...)

- MFSA 2006-53 UniversalBrowserRead privilege escalation

- MFSA 2006-52 PAC privilege escalation using Function.prototype.call

- MFSA 2006-51 Privilege escalation using named-functions and
redefined 'new Object()'

- MFSA 2006-50 JavaScript engine vulnerabilities

- MFSA 2006-49 Heap buffer overwrite on malformed VCard

- MFSA 2006-48 JavaScript new Function race condition

- MFSA 2006-47 Native DOM methods can be hijacked across domains

- MFSA 2006-46 Memory corruption with simultaneous events

- MFSA 2006-45 JavaScript navigator Object Vulnerability

- MFSA 2006-44 Code execution through deleted frame reference"
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey1.0.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69974ef6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-47.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-56.html"
  );
  # http://www.freebsd.org/ports/portaudit/e2a92664-1d60-11db-88cf-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9344f78"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<1.5.0.5,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox>2.*,1<2.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<1.5.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox-devel<3.0.a2006.07.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<1.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<1.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<1.5.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<1.5.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-thunderbird<1.5.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla-devel>0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
