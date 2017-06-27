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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96939);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/05/05 13:47:08 $");

  script_cve_id("CVE-2011-4969", "CVE-2015-0886", "CVE-2017-2598", "CVE-2017-2599", "CVE-2017-2600", "CVE-2017-2601", "CVE-2017-2602", "CVE-2017-2603", "CVE-2017-2604", "CVE-2017-2605", "CVE-2017-2606", "CVE-2017-2607", "CVE-2017-2608", "CVE-2017-2609", "CVE-2017-2610", "CVE-2017-2611", "CVE-2017-2612", "CVE-2017-2613");

  script_name(english:"FreeBSD : jenkins -- multiple vulnerabilities (5cfa9d0c-73d7-4642-af4f-28fbed9e9404)");
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
"Jenkins Security Advisory : DescriptionSECURITY-304 / CVE-2017-2598
Use of AES ECB block cipher mode without IV for encrypting secrets
SECURITY-321 / CVE-2017-2599 Items could be created with same name as
existing item SECURITY-343 / CVE-2017-2600 Node monitor data could be
viewed by low privilege users SECURITY-349 / CVE-2011-4969 Possible
cross-site scripting vulnerability in jQuery bundled with timeline
widget SECURITY-353 / CVE-2017-2601 Persisted cross-site scripting
vulnerability in parameter names and descriptions SECURITY-354 /
CVE-2015-0886 Outdated jbcrypt version bundled with Jenkins
SECURITY-358 / CVE-2017-2602 Pipeline metadata files not blacklisted
in agent-to-master security subsystem SECURITY-362 / CVE-2017-2603
User data leak in disconnected agents' config.xml API SECURITY-371 /
CVE-2017-2604 Low privilege users were able to act on administrative
monitors SECURITY-376 / CVE-2017-2605 Re-key admin monitor leaves
behind unencrypted credentials in upgraded installations SECURITY-380
/ CVE-2017-2606 Internal API allowed access to item names that should
not be visible SECURITY-382 / CVE-2017-2607 Persisted cross-site
scripting vulnerability in console notes SECURITY-383 / CVE-2017-2608
XStream remote code execution vulnerability SECURITY-385 /
CVE-2017-2609 Information disclosure vulnerability in search
suggestions SECURITY-388 / CVE-2017-2610 Persisted cross-site
scripting vulnerability in search suggestions SECURITY-389 /
CVE-2017-2611 Insufficient permission check for periodic processes
SECURITY-392 / CVE-2017-2612 Low privilege users were able to override
JDK download credentials SECURITY-406 / CVE-2017-2613 User creation
CSRF using GET by admins"
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2017-02-01
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f48db5ed"
  );
  # http://www.freebsd.org/ports/portaudit/5cfa9d0c-73d7-4642-af4f-28fbed9e9404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11a0c685"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
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

if (pkg_test(save_report:TRUE, pkg:"jenkins<2.44")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jenkins-lts<2.32.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
