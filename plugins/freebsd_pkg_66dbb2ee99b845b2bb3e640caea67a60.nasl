#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18966);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/09/18 13:33:38 $");

  script_cve_id("CVE-2005-1453");
  script_bugtraq_id(13489, 13492);
  script_xref(name:"Secunia", value:"15252");

  script_name(english:"FreeBSD : leafnode -- fetchnews denial-of-service triggered by transmission abort/timeout (66dbb2ee-99b8-45b2-bb3e-640caea67a60)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When an upstream server aborts the transmission or stops sending data
after the fetchnews program has requested an article header or body,
fetchnews may crash, without querying further servers that are
configured. This can prevent articles from being fetched."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://leafnode.sourceforge.net/leafnode-SA-2005-01.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=80663"
  );
  # http://sourceforge.net/mailarchive/forum.php?thread_id=7186974&forum_id=10210
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77646edf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://article.gmane.org/gmane.network.leafnode.announce/52"
  );
  # http://www.dt.e-technik.uni-dortmund.de/pipermail/leafnode-list/2005q2/000900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c0608f3"
  );
  # http://www.fredi.de/maillist/msg00111.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3414844a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/vulnwatch/2005-q2/0037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.frsirt.com/english/advisories/2005/0468"
  );
  # http://www.freebsd.org/ports/portaudit/66dbb2ee-99b8-45b2-bb3e-640caea67a60.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75e9ae46"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:leafnode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"leafnode>=1.9.48<1.11.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
