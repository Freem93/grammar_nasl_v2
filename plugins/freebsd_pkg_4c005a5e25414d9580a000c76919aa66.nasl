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
  script_id(18929);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/08/09 10:50:38 $");

  script_name(english:"FreeBSD : fd_set -- bitmap index overflow in multiple applications (4c005a5e-2541-4d95-80a0-00c76919aa66)");
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
"3APA3A reports :

If programmer fails to check socket number before using select() or
fd_set macros, it's possible to overwrite memory behind fd_set
structure. Very few select() based application actually check
FD_SETSIZE value. [...]

Depending on vulnerable application it's possible to overwrite
portions of memory. Impact is close to off-by-one overflows, code
execution doesn't seems exploitable."
  );
  # http://www.gotbnc.com/changes.html#2.9.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.archive.org/web/20050429014203/http://www.gotbnc.com/cha"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.security.nnov.ru/advisories/sockets.asp"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110660879328901
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110660879328901"
  );
  # http://www.freebsd.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0cb0688d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:3proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:citadel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dante");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gatekeeper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jabber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rinetd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"gatekeeper<2.2.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"citadel<6.29")) flag++;
if (pkg_test(save_report:TRUE, pkg:"3proxy<0.5.b")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jabber<1.4.3.1_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jabber=1.4.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bnc<2.9.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rinetd<0.62_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dante<1.1.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bld<0.3.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
