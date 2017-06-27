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
  script_id(86519);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");

  script_cve_id("CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871");
  script_xref(name:"FreeBSD", value:"SA-15:25.ntp");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"FreeBSD : ntp -- 13 low- and medium-severity vulnerabilities (c4a18a12-77fc-11e5-a687-206a8a720317)");
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
"ntp.org reports :

NTF's NTP Project has been notified of the following 13 low- and
medium-severity vulnerabilities that are fixed in ntp-4.2.8p4,
released on Wednesday, 21 October 2015 :

- Bug 2941 CVE-2015-7871 NAK to the Future: Symmetric association
authentication bypass via crypto-NAK (Cisco ASIG)

- Bug 2922 CVE-2015-7855 decodenetnum() will ASSERT botch instead of
returning FAIL on some bogus values (IDA)

- Bug 2921 CVE-2015-7854 Password Length Memory Corruption
Vulnerability. (Cisco TALOS)

- Bug 2920 CVE-2015-7853 Invalid length data provided by a custom
refclock driver could cause a buffer overflow. (Cisco TALOS)

- Bug 2919 CVE-2015-7852 ntpq atoascii() Memory Corruption
Vulnerability. (Cisco TALOS)

- Bug 2918 CVE-2015-7851 saveconfig Directory Traversal Vulnerability.
(OpenVMS) (Cisco TALOS)

- Bug 2917 CVE-2015-7850 remote config logfile-keyfile. (Cisco TALOS)

- Bug 2916 CVE-2015-7849 trusted key use-after-free. (Cisco TALOS)

- Bug 2913 CVE-2015-7848 mode 7 loop counter underrun. (Cisco TALOS)

- Bug 2909 CVE-2015-7701 Slow memory leak in CRYPTO_ASSOC. (Tenable)

- Bug 2902 : CVE-2015-7703 configuration directives 'pidfile' and
'driftfile' should only be allowed locally. (RedHat)

- Bug 2901 : CVE-2015-7704, CVE-2015-7705 Clients that receive a KoD
should validate the origin timestamp field. (Boston University)

- Bug 2899 : CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 Incomplete
autokey data packet length checks. (Tenable)

The only generally-exploitable bug in the above list is the crypto-NAK
bug, which has a CVSS2 score of 6.4.

Additionally, three bugs that have already been fixed in ntp-4.2.8 but
were not fixed in ntp-4.2.6 as it was EOL'd have a security component,
but are all below 1.8 CVSS score, so we're reporting them here :

- Bug 2382 : Peer precision < -31 gives division by zero

- Bug 1774 : Segfaults if cryptostats enabled when built without
OpenSSL

- Bug 1593 : ntpd abort in free() with logconfig syntax error"
  );
  # http://support.ntp.org/bin/view/Main/SecurityNotice#Recent_Vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fec88bd0"
  );
  # http://www.freebsd.org/ports/portaudit/c4a18a12-77fc-11e5-a687-206a8a720317.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a0523ed"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"ntp<4.2.8p4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ntp-devel<4.3.76")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
