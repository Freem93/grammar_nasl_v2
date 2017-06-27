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
  script_id(59361);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/21 23:48:17 $");

  script_cve_id("CVE-2012-1667");

  script_name(english:"FreeBSD : dns/bind9* -- zero-length RDATA can cause named to terminate, reveal memory (1ecc0d3f-ae8e-11e1-965b-0024e88a8c98)");
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

Processing of DNS resource records where the rdata field is zero
length may cause various issues for the servers handling them.

Processing of these records may lead to unexpected outcomes. Recursive
servers may crash or disclose some portion of memory to the client.
Secondary servers may crash on restart after transferring a zone
containing these records. Master servers may corrupt zone data if the
zone option 'auto-dnssec' is set to 'maintain'. Other unexpected
problems that are not listed here may also be encountered.

Impact: This issue primarily affects recursive nameservers.
Authoritative nameservers will only be impacted if an administrator
configures experimental record types with no data. If the server is
configured this way, then secondaries can crash on restart after
transferring that zone. Zone data on the master can become corrupted
if the zone with those records has named configured to manage the
DNSSEC key rotation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/software/bind/advisories/cve-2012-1667"
  );
  # http://www.freebsd.org/ports/portaudit/1ecc0d3f-ae8e-11e1-965b-0024e88a8c98.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8efe14f7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind98");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/05");
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

if (pkg_test(save_report:TRUE, pkg:"bind99<9.9.1.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind98<9.8.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind97<9.7.6.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind96<9.6.3.1.ESV.R7.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
