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
  script_id(62054);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 23:48:19 $");

  script_cve_id("CVE-2012-3547");

  script_name(english:"FreeBSD : freeradius -- arbitrary code execution for TLS-based authentication (3bbbe3aa-fbeb-11e1-8bd8-0022156e8794)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"freeRADIUS security team reports :

Overflow in EAP-TLS for 2.1.10, 2.1.11 and 2.1.12.

The issue was found by Timo Warns, and communicated to
security@freeradius.org. A sample exploit for the issue was included
in the notification.

The vulnerability was created in commit a368a6f4f4aaf on August 18,
2010. Vulnerable versions include 2.1.10, 2.1.11, and 2.1.12. Also
anyone running the git 'master' branch after August 18, 2010 is
vulnerable.

All sites using TLS-based EAP methods and the above versions are
vulnerable. The only configuration change which can avoid the issue is
to disable EAP-TLS, EAP-TTLS, and PEAP.

An external attacker can use this vulnerability to over-write the
stack frame of the RADIUS server, and cause it to crash. In addition,
more sophisticated attacks may gain additional privileges on the
system running the RADIUS server.

This attack does not require local network access to the RADIUS
server. It can be done by an attacker through a WiFi Access Point, so
long as the Access Point is configured to use 802.1X authentication
with the RADIUS server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://freeradius.org/security.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pre-cert.de/advisories/PRE-SA-2012-06.txt"
  );
  # http://www.freebsd.org/ports/portaudit/3bbbe3aa-fbeb-11e1-8bd8-0022156e8794.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b165c72b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:freeradius");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/12");
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

if (pkg_test(save_report:TRUE, pkg:"freeradius>=2.1.10<2.1.12_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
