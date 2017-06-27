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
  script_id(84780);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2727", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730", "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2742", "CVE-2015-2743", "CVE-2015-4000");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (44d9daee-940c-4179-86bb-6e3ffd617869) (Logjam)");
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
"The Mozilla Project reports :

MFSA 2015-59 Miscellaneous memory safety hazards (rv:39.0 / rv:31.8 /
rv:38.1)

MFSA 2015-60 Local files or privileged URLs in pages can be opened
into new tabs

MFSA 2015-61 Type confusion in Indexed Database Manager

MFSA 2015-62 Out-of-bound read while computing an oscillator rendering
range in Web Audio

MFSA 2015-63 Use-after-free in Content Policy due to microtask
execution error

MFSA 2015-64 ECDSA signature validation fails to handle some
signatures correctly

MFSA 2015-65 Use-after-free in workers while using XMLHttpRequest

MFSA 2015-66 Vulnerabilities found through code inspection

MFSA 2015-67 Key pinning is ignored when overridable errors are
encountered

MFSA 2015-68 OS X crash reports may contain entered key press
information

MFSA 2015-69 Privilege escalation through internal workers

MFSA 2015-70 NSS accepts export-length DHE keys with regular DHE
cipher suites

MFSA 2015-71 NSS incorrectly permits skipping of ServerKeyExchange"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-59/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-60/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-61/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-62/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-63/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-64/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-65/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-66/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-67/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-68/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-69/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-70/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2015-71/"
  );
  # http://www.freebsd.org/ports/portaudit/44d9daee-940c-4179-86bb-6e3ffd617869.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ed3820f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<39.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<39.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.35")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.35")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<31.8.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr>=38.0,1<38.1.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<31.8.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul>=38.0<38.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<31.8.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>=38.0<38.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<31.8.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird>=38.0<38.1.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
