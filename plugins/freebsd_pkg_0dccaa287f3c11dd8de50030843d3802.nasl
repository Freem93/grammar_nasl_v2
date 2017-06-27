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
  script_id(34164);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:31:55 $");

  script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3144");
  script_xref(name:"Secunia", value:"31305");

  script_name(english:"FreeBSD : python -- multiple vulnerabilities (0dccaa28-7f3c-11dd-8de5-0030843d3802)");
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
"Secunia reports :

Some vulnerabilities have been reported in Python, where some have
unknown impact and others can potentially be exploited by malicious
people to cause a DoS (Denial of Service) or to compromise a
vulnerable system.

Various integer overflow errors exist in core modules e.g.
stringobject, unicodeobject, bufferobject, longobject, tupleobject,
stropmodule, gcmodule, mmapmodule.

An integer overflow in the hashlib module can lead to an unreliable
cryptographic digest results.

Integer overflow errors in the processing of unicode strings can be
exploited to cause buffer overflows on 32-bit systems.

An integer overflow exists in the PyOS_vsnprintf() function on
architectures that do not have a 'vsnprintf()' function.

An integer underflow error in the PyOS_vsnprintf() function when
passing zero-length strings can lead to memory corruption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.python.org/issue2620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.python.org/issue2588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.python.org/issue2589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mail.python.org/pipermail/python-checkins/2008-July/072276.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mail.python.org/pipermail/python-checkins/2008-July/072174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mail.python.org/pipermail/python-checkins/2008-June/070481.html"
  );
  # http://www.freebsd.org/ports/portaudit/0dccaa28-7f3c-11dd-8de5-0030843d3802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8263eb57"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python25");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"python24<2.4.5_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python25<2.5.2_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python23>0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
