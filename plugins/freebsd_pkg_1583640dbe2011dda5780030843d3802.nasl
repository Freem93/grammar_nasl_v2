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
  script_id(34976);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/21 23:43:35 $");

  script_cve_id("CVE-2008-4314");
  script_xref(name:"Secunia", value:"32813");

  script_name(english:"FreeBSD : samba -- potential leakage of arbitrary memory contents (1583640d-be20-11dd-a578-0030843d3802)");
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
"Samba Team reports :

Samba 3.0.29 and beyond contain a change to deal with gcc 4
optimizations. Part of the change modified range checking for
client-generated offsets of secondary trans, trans2 and nttrans
requests. These requests are used to transfer arbitrary amounts of
memory from clients to servers and back using small SMB requests and
contain two offsets: One offset (A) pointing into the PDU sent by the
client and one (B) to direct the transferred contents into the buffer
built on the server side. While the range checking for offset (B) is
correct, a cut and paste error lets offset (A) pass completely
unchecked against overflow.

The buffers passed into trans, trans2 and nttrans undergo higher-level
processing like DCE/RPC requests or listing directories. The missing
bounds check means that a malicious client can make the server do this
higher-level processing on arbitrary memory contents of the smbd
process handling the request. It is unknown if that can be abused to
pass arbitrary memory contents back to the client, but an important
barrier is missing from the affected Samba versions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2008-4314.html"
  );
  # http://www.freebsd.org/ports/portaudit/1583640d-be20-11dd-a578-0030843d3802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b47989e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba32-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"samba>=3.0.29,1<3.0.32_2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba3>=3.0.29,1<3.0.32_2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-samba>=3.0.29,1<3.0.32_2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba32-devel<3.2.4_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
