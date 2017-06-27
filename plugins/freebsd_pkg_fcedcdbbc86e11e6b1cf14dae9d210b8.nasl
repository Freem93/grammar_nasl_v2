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
  script_id(96123);
  script_version("$Revision: 3.9 $");
  script_cvs_date("$Date: 2017/05/05 13:47:08 $");

  script_cve_id("CVE-2016-7426", "CVE-2016-7427", "CVE-2016-7428", "CVE-2016-7431", "CVE-2016-7433", "CVE-2016-7434", "CVE-2016-9310", "CVE-2016-9311");
  script_xref(name:"FreeBSD", value:"SA-16:39.ntp");

  script_name(english:"FreeBSD : FreeBSD -- Multiple vulnerabilities of ntp (fcedcdbb-c86e-11e6-b1cf-14dae9d210b8)");
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

CVE-2016-9311: Trap crash, Reported by Matthew Van Gundy of Cisco
ASIG.

CVE-2016-9310: Mode 6 unauthenticated trap information disclosure and
DDoS vector. Reported by Matthew Van Gundy of Cisco ASIG.

CVE-2016-7427: Broadcast Mode Replay Prevention DoS. Reported by
Matthew Van Gundy of Cisco ASIG.

CVE-2016-7428: Broadcast Mode Poll Interval Enforcement DoS. Reported
by Matthew Van Gundy of Cisco ASIG.

CVE-2016-7431: Regression: 010-origin: Zero Origin Timestamp Bypass.
Reported by Sharon Goldberg and Aanchal Malhotra of Boston University.

CVE-2016-7434: NULL pointer dereference in
_IO_str_init_static_internal(). Reported by Magnus Stubman.

CVE-2016-7426: Client rate limiting and server responses. Reported by
Miroslav Lichvar of Red Hat.

CVE-2016-7433: Reboot sync calculation problem. Reported independently
by Brian Utterback of Oracle, and by Sharon Goldberg and Aanchal
Malhotra of Boston University. Impact : A remote attacker who can send
a specially crafted packet to cause a NULL pointer dereference that
will crash ntpd, resulting in a Denial of Service. [CVE-2016-9311]

An exploitable configuration modification vulnerability exists in the
control mode (mode 6) functionality of ntpd. If, against long-standing
BCP recommendations, 'restrict default noquery ...' is not specified,
a specially crafted control mode packet can set ntpd traps, providing
information disclosure and DDoS amplification, and unset ntpd traps,
disabling legitimate monitoring by an attacker from remote.
[CVE-2016-9310]

An attacker with access to the NTP broadcast domain can periodically
inject specially crafted broadcast mode NTP packets into the broadcast
domain which, while being logged by ntpd, can cause ntpd to reject
broadcast mode packets from legitimate NTP broadcast servers.
[CVE-2016-7427]

An attacker with access to the NTP broadcast domain can send specially
crafted broadcast mode NTP packets to the broadcast domain which,
while being logged by ntpd, will cause ntpd to reject broadcast mode
packets from legitimate NTP broadcast servers. [CVE-2016-7428]

Origin timestamp problems were fixed in ntp 4.2.8p6. However,
subsequent timestamp validation checks introduced a regression in the
handling of some Zero origin timestamp checks. [CVE-2016-7431]

If ntpd is configured to allow mrulist query requests from a server
that sends a crafted malicious packet, ntpd will crash on receipt of
that crafted malicious mrulist query packet. [CVE-2016-7434]

An attacker who knows the sources (e.g., from an IPv4 refid in server
response) and knows the system is (mis)configured in this way can
periodically send packets with spoofed source address to keep the rate
limiting activated and prevent ntpd from accepting valid responses
from its sources. [CVE-2016-7426]

Ntp Bug 2085 described a condition where the root delay was included
twice, causing the jitter value to be higher than expected. Due to a
misinterpretation of a small-print variable in The Book, the fix for
this problem was incorrect, resulting in a root distance that did not
include the peer dispersion. The calculations and formulas have been
reviewed and reconciled, and the code has been updated accordingly.
[CVE-2016-7433]"
  );
  # http://www.freebsd.org/ports/portaudit/fcedcdbb-c86e-11e6-b1cf-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc8befee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:FreeBSD");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=11.0<11.0_6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.3<10.3_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.2<10.2_28")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=10.1<10.1_45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"FreeBSD>=9.3<9.3_53")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
