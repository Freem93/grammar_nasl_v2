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

include("compat.inc");

if (description)
{
  script_id(90742);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/02/27 15:13:33 $");

  script_cve_id("CVE-2015-7704", "CVE-2015-8138", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519");
  script_xref(name:"FreeBSD", value:"SA-16:16.ntp");

  script_name(english:"FreeBSD : ntp -- multiple vulnerabilities (b2487d9a-0c30-11e6-acd0-d050996490d0)");
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
"Network Time Foundation reports :

NTF's NTP Project has been notified of the following low- and
medium-severity vulnerabilities that are fixed in ntp-4.2.8p7,
released on Tuesday, 26 April 2016 :

- Bug 3020 / CVE-2016-1551: Refclock impersonation vulnerability, AKA:
refclock-peering. Reported by Matt Street and others of Cisco ASIG

- Bug 3012 / CVE-2016-1549: Sybil vulnerability : ephemeral
association attack, AKA: ntp-sybil - MITIGATION ONLY. Reported by
Matthew Van Gundy of Cisco ASIG

- Bug 3011 / CVE-2016-2516: Duplicate IPs on unconfig directives will
cause an assertion botch. Reported by Yihan Lian of the Cloud Security
Team, Qihoo 360

- Bug 3010 / CVE-2016-2517: Remote configuration trustedkey/requestkey
values are not properly validated. Reported by Yihan Lian of the Cloud
Security Team, Qihoo 360

- Bug 3009 / CVE-2016-2518: Crafted addpeer with hmode > 7 causes
array wraparound with MATCH_ASSOC. Reported by Yihan Lian of the Cloud
Security Team, Qihoo 360

- Bug 3008 / CVE-2016-2519: ctl_getitem() return value not always
checked. Reported by Yihan Lian of the Cloud Security Team, Qihoo 360

- Bug 3007 / CVE-2016-1547: Validate crypto-NAKs, AKA: nak-dos.
Reported by Stephen Gray and Matthew Van Gundy of Cisco ASIG

- Bug 2978 / CVE-2016-1548: Interleave-pivot - MITIGATION ONLY.
Reported by Miroslav Lichvar of RedHat and separately by Jonathan
Gardner of Cisco ASIG.

- Bug 2952 / CVE-2015-7704: KoD fix: peer associations were broken by
the fix for NtpBug2901, AKA: Symmetric active/passive mode is broken.
Reported by Michael Tatarinov, NTP Project Developer Volunteer

- Bug 2945 / Bug 2901 / CVE-2015-8138: Zero Origin Timestamp Bypass,
AKA: Additional KoD Checks. Reported by Jonathan Gardner of Cisco ASIG

- Bug 2879 / CVE-2016-1550: Improve NTP security against buffer
comparison timing attacks, authdecrypt-timing, AKA:
authdecrypt-timing. Reported independently by Loganaden Velvindron,
and Matthew Van Gundy and Stephen Gray of Cisco ASIG."
  );
  # http://support.ntp.org/bin/view/Main/SecurityNotice#April_2016_NTP_4_2_8p7_Security
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a6d1cf4"
  );
  # http://www.freebsd.org/ports/portaudit/b2487d9a-0c30-11e6-acd0-d050996490d0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce7ee8a3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"ntp<4.2.8p7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ntp-devel<4.3.92")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
