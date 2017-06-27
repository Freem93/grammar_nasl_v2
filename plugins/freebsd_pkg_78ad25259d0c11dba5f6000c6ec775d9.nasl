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
  script_id(23988);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:31:56 $");

  script_cve_id("CVE-2007-0126", "CVE-2007-0127");

  script_name(english:"FreeBSD : opera -- multiple vulnerabilities (78ad2525-9d0c-11db-a5f6-000c6ec775d9)");
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
"iDefense reports :

The vulnerability specifically exists due to Opera improperly
processing a JPEG DHT marker. The DHT marker is used to define a
Huffman Table which is used for decoding the image data. An invalid
number of index bytes in the DHT marker will trigger a heap overflow
with partially user controlled data.

Exploitation of this vulnerability would allow an attacker to execute
arbitrary code on the affected host. The attacker would first need to
construct a website containing the malicious image and trick the
vulnerable user into visiting the site. This would trigger the
vulnerability and allow the code to execute with the privileges of the
local user.

A flaw exists within Opera's JavaScript SVG implementation. When
processing a createSVGTransformFromMatrix request Opera does not
properly validate the type of object passed to the function. Passing
an incorrect object to this function can result in it using a pointer
that is user controlled when it attempts to make the virtual function
call.

Exploitation of this vulnerability would allow an attacker to execute
arbitrary code on the affected host. The attacker would first need to
construct a website containing the malicious JavaScript and trick the
vulnerable user into visiting the site. This would trigger the
vulnerability and allow the code to execute with the privileges of the
local user."
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=457
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05bc3cca"
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=458
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d4eeada"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/search/supsearch.dml?index=851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/search/supsearch.dml?index=852"
  );
  # http://www.freebsd.org/ports/portaudit/78ad2525-9d0c-11db-a5f6-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09e73d33"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"opera<9.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opera-devel<9.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<9.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
