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

include("compat.inc");

if (description)
{
  script_id(18849);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/22 11:11:54 $");

  script_name(english:"FreeBSD : opera -- multiple vulnerabilities in Java implementation (1489df94-6bcb-11d9-a21e-000a95bc6fae)");
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
"Marc Schoenefeld reports :

Opera 7.54 is vulnerable to leakage of the java sandbox, allowing
malicious applets to gain unacceptable privileges. This allows them to
be used for information gathering (spying) of local identity
information and system configurations as well as causing annoying
crash effects.

Opera 754 [sic] which was released Aug 5,2004 is vulnerable to the
XSLT processor covert channel attack, which was corrected with JRE
1.4.2_05 [released in July 04], but in disadvantage to the users the
opera packaging guys chose to bundle the JRE 1.4.2_04 [...]

Internal pointer DoS exploitation: Opera.jar contains the opera
replacement of the java plugin. It therefore handles communication
between JavaScript and the Java VM via the liveconnect protocol. The
public class EcmaScriptObject exposes a system memory pointer to the
java address space, by constructing a special variant of this type an
internal cache table can be polluted by false entries that infer
proper function of the JSObject class and in the following
proof-of-concept crash the browser.

Exposure of location of local java installation Sniffing the URL
classpath allows to retrieve the URLs of the bootstrap class path and
therefore the JDK installation directory.

Exposure of local user name to an untrusted applet An attacker could
use the sun.security.krb5.Credentials class to retrieve the name of
the currently logged in user and parse his home directory from the
information which is provided by the thrown
java.security.AccessControlException."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110088923127820
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110088923127820"
  );
  # http://www.freebsd.org/ports/portaudit/1489df94-6bcb-11d9-a21e-000a95bc6fae.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d239954"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/24");
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

if (pkg_test(save_report:TRUE, pkg:"opera<7.54.20041210")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opera-devel<7.54.20041210")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<7.54.20041210")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
