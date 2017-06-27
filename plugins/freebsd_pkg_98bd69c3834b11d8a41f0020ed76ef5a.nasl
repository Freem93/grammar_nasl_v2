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
  script_id(19044);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/06/22 00:02:02 $");

  script_cve_id("CVE-2004-0224");
  script_bugtraq_id(9845);
  script_osvdb_id(4194, 6927);
  script_xref(name:"Secunia", value:"11087");

  script_name(english:"FreeBSD : Courier mail services: remotely exploitable buffer overflows (98bd69c3-834b-11d8-a41f-0020ed76ef5a)");
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
"The Courier set of mail services use a common Unicode library. This
library contains buffer overflows in the converters for two popular
Japanese character encodings. These overflows may be remotely
exploitable, triggered by a maliciously formatted email message that
is later processed by one of the Courier mail services. From the
release notes for the corrected versions of the Courier set of mail
services :

iso2022jp.c: Converters became (upper-)compatible with ISO-2022-JP
(RFC1468 / JIS X 0208:1997 Annex 2) and ISO-2022-JP-1 (RFC2237).
Buffer overflow vulnerability (when Unicode character is out of BMP
range) has been closed. Convert error handling was implemented.

shiftjis.c: Broken SHIFT_JIS converters has been fixed and became
(upper-)compatible with Shifted Encoding Method (JIS X 0208:1997 Annex
1). Buffer overflow vulnerability (when Unicode character is out of
BMP range) has been closed. Convert error handling was implemented."
  );
  # http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/iso2022jp.c?rev=1.10&view=markup
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a3ae431"
  );
  # http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/shiftjis.c?rev=1.6&view=markup
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6efec52b"
  );
  # http://www.freebsd.org/ports/portaudit/98bd69c3-834b-11d8-a41f-0020ed76ef5a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48126b13"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:courier-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sqwebmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/31");
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

if (pkg_test(save_report:TRUE, pkg:"courier<0.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"courier-imap<3.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sqwebmail<4.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
