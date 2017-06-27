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
  script_id(21414);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/09 15:44:46 $");

  script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1852", "CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
  script_bugtraq_id(14345);

  script_name(english:"FreeBSD : libgadu -- multiple vulnerabilities (3b4a6982-0b24-11da-bc08-0001020eed82)");
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
"Wojtek Kaniewski reports :

Multiple vulnerabilities have been found in libgadu, a library for
handling Gadu-Gadu instant messaging protocol. It is a part of ekg, a
Gadu-Gadu client, but is widely used in other clients. Also some of
the user contributed scripts were found to behave in an insecure
manner.

- integer overflow in libgadu (CVE-2005-1852) that could be triggered
by an incomming message and lead to application crash and/or remote
code execution

- insecure file creation (CVE-2005-1850) and shell command injection
(CVE-2005-1851) in other user contributed scripts (discovered by
Marcin Owsiany and Wojtek Kaniewski)

- several signedness errors in libgadu that could be triggered by an
incomming network data or an application passing invalid user input to
the library

- memory alignment errors in libgadu that could be triggered by an
incomming message and lead to bus errors on architectures like SPARC

- endianness errors in libgadu that could cause invalid behaviour of
applications on big-endian architectures"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=112198499417250
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=112198499417250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://gaim.sourceforge.net/security/?id=20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20050721-1.txt"
  );
  # http://www.freebsd.org/ports/portaudit/3b4a6982-0b24-11da-bc08-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03d7176c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:centericq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ko-gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pl-ekg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"gaim<1.4.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-gaim<1.4.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-gaim<1.4.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-gaim<1.4.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kdenetwork>3.2.2<3.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pl-ekg<1.6r3,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"centericq<4.21.0_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
