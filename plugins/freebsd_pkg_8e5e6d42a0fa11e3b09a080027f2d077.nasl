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
  script_id(72768);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2014-1912");
  script_bugtraq_id(65379);

  script_name(english:"FreeBSD : Python -- buffer overflow in socket.recvfrom_into() (8e5e6d42-a0fa-11e3-b09a-080027f2d077)");
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
"Vincent Danen via Red Hat Issue Tracker reports :

A vulnerability was reported in Python's socket module, due to a
boundary error within the sock_recvfrom_into() function, which could
be exploited to cause a buffer overflow. This could be used to crash a
Python application that uses the socket.recvfrom_info() function or,
possibly, execute arbitrary code with the permissions of the user
running vulnerable Python code.

This vulnerable function, socket.recvfrom_into(), was introduced in
Python 2.5. Earlier versions are not affected by this flaw."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mail.python.org/pipermail/python-dev/2014-February/132758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.python.org/issue20246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1062370"
  );
  # http://www.freebsd.org/ports/portaudit/8e5e6d42-a0fa-11e3-b09a-080027f2d077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61febd11"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python33");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"python27<=2.7.6_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python31<=3.1.5_10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python32<=3.2.5_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python33<=3.3.3_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
