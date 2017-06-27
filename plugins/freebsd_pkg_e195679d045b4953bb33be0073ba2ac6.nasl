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
  script_id(93145);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:14:42 $");

  script_cve_id("CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4449", "CVE-2016-4483");

  script_name(english:"FreeBSD : libxml2 -- multiple vulnabilities (e195679d-045b-4953-bb33-be0073ba2ac6)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel Veillard reports :

More format string warnings with possible format string vulnerability
(David Kilzer)

Avoid building recursive entities (Daniel Veillard)

Heap-based buffer overread in htmlCurrentChar (Pranjal Jumde)

Heap-based buffer-underreads due to xmlParseName (David Kilzer)

Heap use-after-free in xmlSAX2AttributeNs (Pranjal Jumde)

Heap use-after-free in htmlParsePubidLiteral and htmlParseSystemiteral
(Pranjal Jumde)

Fix some format string warnings with possible format string
vulnerability (David Kilzer)

Detect change of encoding when parsing HTML names (Hugh Davenport)

Fix inappropriate fetch of entities content (Daniel Veillard)

Bug 759398: Heap use-after-free in xmlDictComputeFastKey (Pranjal
Jumde)

Bug 758605: Heap-based buffer overread in xmlDictAddString (Pranjal
Jumde)

Bug 758588: Heap-based buffer overread in
xmlParserPrintFileContextInternal (David Kilzer)

Bug 757711: heap-buffer-overflow in xmlFAParsePosCharGroup (Pranjal
Jumde)

Add missing increments of recursion depth counter to XML parser.
(Peter Simons)

Fix NULL pointer deref in XPointer range-to"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mail.gnome.org/archives/xml/2016-May/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=759398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=758605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=758588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.gnome.org/show_bug.cgi?id=757711"
  );
  # https://git.gnome.org/browse/libxml2/patch/?id=d8083bf77955b7879c1290f0c0a24ab8cc70f7fb
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96b5bf04"
  );
  # http://www.freebsd.org/ports/portaudit/e195679d-045b-4953-bb33-be0073ba2ac6.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e0c0388"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"libxml2<2.9.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
