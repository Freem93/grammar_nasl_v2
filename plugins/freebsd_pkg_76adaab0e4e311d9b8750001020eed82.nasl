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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18986);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_cve_id("CVE-2005-1281", "CVE-2005-1456", "CVE-2005-1457", "CVE-2005-1458", "CVE-2005-1459", "CVE-2005-1460", "CVE-2005-1461", "CVE-2005-1462", "CVE-2005-1463", "CVE-2005-1464", "CVE-2005-1465", "CVE-2005-1466", "CVE-2005-1467", "CVE-2005-1468", "CVE-2005-1469", "CVE-2005-1470");
  script_bugtraq_id(13391, 13504, 13567);

  script_name(english:"FreeBSD : ethereal -- multiple protocol dissectors vulnerabilities (76adaab0-e4e3-11d9-b875-0001020eed82)");
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
"An Ethreal Security Advisories reports :

An aggressive testing program as well as independent discovery has
turned up a multitude of security issues :

- The ANSI A dissector was susceptible to format string
vulnerabilities. Discovered by Bryan Fulton.

- The GSM MAP dissector could crash.

- The AIM dissector could cause a crash.

- The DISTCC dissector was susceptible to a buffer overflow.
Discovered by Ilja van Sprundel

- The FCELS dissector was susceptible to a buffer overflow. Discovered
by Neil Kettle

- The SIP dissector was susceptible to a buffer overflow. Discovered
by Ejovi Nuwere.

- The KINK dissector was susceptible to a NULL pointer exception,
endless looping, and other problems.

- The LMP dissector was susceptible to an endless loop.

- The Telnet dissector could abort.

- The TZSP dissector could cause a segmentation fault.

- The WSP dissector was susceptible to a NULL pointer exception and
assertions.

- The 802.3 Slow protocols dissector could throw an assertion.

- The BER dissector could throw assertions.

- The SMB Mailslot dissector was susceptible to a NULL pointer
exception and could throw assertions.

- The H.245 dissector was susceptible to a NULL pointer exception.

- The Bittorrent dissector could cause a segmentation fault.

- The SMB dissector could cause a segmentation fault and throw
assertions.

- The Fibre Channel dissector could cause a crash.

- The DICOM dissector could attempt to allocate large amounts of
memory.

- The MGCP dissector was susceptible to a NULL pointer exception,
could loop indefinitely, and segfault.

- The RSVP dissector could loop indefinitely.

- The DHCP dissector was susceptible to format string vulnerabilities,
and could abort.

- The SRVLOC dissector could crash unexpectedly or go into an infinite
loop.

- The EIGRP dissector could loop indefinitely.

- The ISIS dissector could overflow a buffer.

- The CMIP, CMP, CMS, CRMF, ESS, OCSP, PKIX1Explitit, PKIX Qualified,
and X.509 dissectors could overflow buffers.

- The NDPS dissector could exhaust system memory or cause an
assertion, or crash.

- The Q.931 dissector could try to free a NULL pointer and overflow a
buffer.

- The IAX2 dissector could throw an assertion.

- The ICEP dissector could try to free the same memory twice.

- The MEGACO dissector was susceptible to an infinite loop and a
buffer overflow.

- The DLSw dissector was susceptible to an infinite loop.

- The RPC dissector was susceptible to a NULL pointer exception.

- The NCP dissector could overflow a buffer or loop for a large amount
of time.

- The RADIUS dissector could throw an assertion.

- The GSM dissector could access an invalid pointer.

- The SMB PIPE dissector could throw an assertion.

- The L2TP dissector was susceptible to an infinite loop.

- The SMB NETLOGON dissector could dereference a NULL pointer.

- The MRDISC dissector could throw an assertion.

- The ISUP dissector could overflow a buffer or cause a segmentation
fault.

- The LDAP dissector could crash.

- The TCAP dissector could overflow a buffer or throw an assertion.

- The NTLMSSP dissector could crash.

- The Presentation dissector could overflow a buffer.

- Additionally, a number of dissectors could throw an assertion when
passing an invalid protocol tree item length."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00019.html"
  );
  # http://www.freebsd.org/ports/portaudit/76adaab0-e4e3-11d9-b875-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aad2f6a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"ethereal>=0.8.14<0.10.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ethereal-lite>=0.8.14<0.10.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal>=0.8.14<0.10.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal-lite>=0.8.14<0.10.11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
