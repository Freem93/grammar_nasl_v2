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
  script_id(34770);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/22 00:10:43 $");

  script_cve_id("CVE-2008-4309");

  script_name(english:"FreeBSD : net-snmp -- DoS for SNMP agent via crafted GETBULK request (daf045d7-b211-11dd-a987-000c29ca8953)");
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
"Wes Hardaker reports through sourceforge.net forum :

SECURITY ISSUE: A bug in the getbulk handling code could let anyone
with even minimal access crash the agent. If you have open access to
your snmp agents (bad bad bad; stop doing that!) or if you don't trust
everyone that does have access to your agents you should updated
immediately to prevent potential denial of service attacks.

Description at cve.mitre.org additionally clarifies :

Integer overflow in the netsnmp_create_subtree_cache function in
agent/snmp_agent.c in net-snmp 5.4 before 5.4.2.1, 5.3 before 5.3.2.3,
and 5.2 before 5.2.5.1 allows remote attackers to cause a denial of
service (crash) via a crafted SNMP GETBULK request, which triggers a
heap-based buffer overflow, related to the number of responses or
repeats."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/forum/forum.php?forum_id=882903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2008/10/31/1"
  );
  # http://net-snmp.svn.sourceforge.net/viewvc/net-snmp/tags/Ext-5-2-5-1/net-snmp/agent/snmp_agent.c?r1=17271&r2=17272&pathrev=17272
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38116fd5"
  );
  # http://www.freebsd.org/ports/portaudit/daf045d7-b211-11dd-a987-000c29ca8953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0f66152"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:net-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/14");
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

if (pkg_test(save_report:TRUE, pkg:"net-snmp>5.4<5.4.2.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"net-snmp>5.3<5.3.2.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
