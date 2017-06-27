#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(60115);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/22 00:10:42 $");

  script_cve_id("CVE-2012-3570", "CVE-2012-3571", "CVE-2012-3954");

  script_name(english:"FreeBSD : isc-dhcp -- multiple vulnerabilities (c7fa3618-d5ff-11e1-90a2-000c299b62e1)");
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
"ISC reports :

An unexpected client identifier parameter can cause the ISC DHCP
daemon to segmentation fault when running in DHCPv6 mode, resulting in
a denial of service to further client requests. In order to exploit
this condition, an attacker must be able to send requests to the DHCP
server.

An error in the handling of malformed client identifiers can cause a
DHCP server running affected versions (see 'Impact') to enter a state
where further client requests are not processed and the server process
loops endlessly, consuming all available CPU cycles. Under normal
circumstances this condition should not be triggered, but a
non-conforming or malicious client could deliberately trigger it in a
vulnerable server. In order to exploit this condition an attacker must
be able to send requests to the DHCP server.

Two memory leaks have been found and fixed in ISC DHCP. Both are
reproducible when running in DHCPv6 mode (with the -6 command-line
argument.) The first leak is confirmed to only affect servers
operating in DHCPv6 mode, but based on initial code analysis the
second may theoretically affect DHCPv4 servers (though this has not
been demonstrated.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-00714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-00712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-00737"
  );
  # http://www.freebsd.org/ports/portaudit/c7fa3618-d5ff-11e1-90a2-000c299b62e1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4692b76"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:isc-dhcp41-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:isc-dhcp42-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"isc-dhcp41-server<4.1.e_5,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"isc-dhcp42-server<4.2.4_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
