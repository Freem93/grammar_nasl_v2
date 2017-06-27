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
  script_id(92927);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/05 16:04:16 $");

  script_cve_id("CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_xref(name:"FreeBSD", value:"SA-16:24.ntp");

  script_name(english:"FreeBSD : FreeBSD -- Multiple ntp vulnerabilities (7cfcea05-600a-11e6-a6c3-14dae9d210b8)");
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
"Multiple vulnerabilities have been discovered in the NTP suite :

The fix for Sec 3007 in ntp-4.2.8p7 contained a bug that could cause
ntpd to crash. [CVE-2016-4957, Reported by Nicolas Edet of Cisco]

An attacker who knows the origin timestamp and can send a spoofed
packet containing a CRYPTO-NAK to an ephemeral peer target before any
other response is sent can demobilize that association.
[CVE-2016-4953, Reported by Miroslav Lichvar of Red Hat]

An attacker who is able to spoof packets with correct origin
timestamps from enough servers before the expected response packets
arrive at the target machine can affect some peer variables and, for
example, cause a false leap indication to be set. [CVE-2016-4954,
Reported by Jakub Prokes of Red Hat]

An attacker who is able to spoof a packet with a correct origin
timestamp before the expected response packet arrives at the target
machine can send a CRYPTO_NAK or a bad MAC and cause the association's
peer variables to be cleared. If this can be done often enough, it
will prevent that association from working. [CVE-2016-4955, Reported
by Miroslav Lichvar of Red Hat]

The fix for NtpBug2978 does not cover broadcast associations, so
broadcast clients can be triggered to flip into interleave mode.
[CVE-2016-4956, Reported by Miroslav Lichvar of Red Hat.] Impact :
Malicious remote attackers may be able to break time synchronization,
or cause the ntpd(8) daemon to crash."
  );
  # http://www.freebsd.org/ports/portaudit/7cfcea05-600a-11e6-a6c3-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?881a35c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:FreeBSD");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;

if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.3<10.3_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.2<10.2_19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.1<10.1_36")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=9.3<9.3_44")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
