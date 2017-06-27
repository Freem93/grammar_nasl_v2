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
  script_id(19344);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_name(english:"FreeBSD : ethereal -- multiple protocol dissectors vulnerabilities (5d51d245-00ca-11da-bc08-0001020eed82)");
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

Our testing program has turned up several more security issues :

- The LDAP dissector could free static memory and crash.

- The AgentX dissector could crash.

- The 802.3 dissector could go into an infinite loop.

- The PER dissector could abort.

- The DHCP dissector could go into an infinite loop.

- The BER dissector could abort or loop infinitely.

- The MEGACO dissector could go into an infinite loop.

- The GIOP dissector could dereference a NULL pointer.

- The SMB dissector was susceptible to a buffer overflow.

- The WBXML could dereference a NULL pointer.

- The H1 dissector could go into an infinite loop.

- The DOCSIS dissector could cause a crash.

- The SMPP dissector could go into an infinite loop.

- SCTP graphs could crash.

- The HTTP dissector could crash.

- The SMB dissector could go into a large loop.

- The DCERPC dissector could crash.

- Several dissectors could crash while reassembling packets.

Steve Grubb at Red Hat found the following issues :

- The CAMEL dissector could dereference a NULL pointer.

- The DHCP dissector could crash.

- The CAMEL dissector could crash.

- The PER dissector could crash.

- The RADIUS dissector could crash.

- The Telnet dissector could crash.

- The IS-IS LSP dissector could crash.

- The NCP dissector could crash.

iDEFENSE found the following issues :

- Several dissectors were susceptible to a format string overflow.
Impact : It may be possible to make Ethereal crash, use up available
memory, or run arbitrary code by injecting a purposefully malformed
packet onto the wire or by convincing someone to read a malformed
packet trace file."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00020.html"
  );
  # http://www.freebsd.org/ports/portaudit/5d51d245-00ca-11da-bc08-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43eee165"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/01");
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

if (pkg_test(save_report:TRUE, pkg:"ethereal>=0.8.5<0.10.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ethereal-lite>=0.8.5<0.10.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal>=0.8.5<0.10.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal-lite>=0.8.5<0.10.12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
