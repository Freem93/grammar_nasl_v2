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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63589);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/22 00:10:43 $");

  script_cve_id("CVE-2013-0433");
  script_xref(name:"CERT", value:"625617");

  script_name(english:"FreeBSD : java 7.x -- security manager bypass (d5e0317e-5e45-11e2-a113-c48508086173)");
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
"US CERT reports :

Java 7 Update 10 and earlier versions of Java 7 contain a
vulnerability that can allow a remote, unauthenticated attacker to
execute arbitrary code on a vulnerable system.

The Java JRE plug-in provides its own Security Manager. Typically, a
web applet runs with a security manager provided by the browser or
Java Web Start plugin. Oracle's document states, 'If there is a
security manager already installed, this method first calls the
security manager's checkPermission method with a
RuntimePermission('setSecurityManager') permission to ensure it's safe
to replace the existing security manager. This may result in throwing
a SecurityException'.

By leveraging the vulnerability in the Java Management Extensions
(JMX) MBean components, unprivileged Java code can access restricted
classes. By using that vulnerability in conjunction with a second
vulnerability involving the Reflection API and the invokeWithArguments
method of the MethodHandle class, an untrusted Java applet can
escalate its privileges by calling the the setSecurityManager()
function to allow full privileges, without requiring code signing.
Oracle Java 7 update 10 and earlier Java 7 versions are affected. The
invokeWithArguments method was introduced with Java 7, so therefore
Java 6 is not affected.

This vulnerability is being attacked in the wild, and is reported to
be incorporated into exploit kits. Exploit code for this vulnerability
is also publicly available.

Esteban Guillardoy from Immunity Inc. additionally clarifies on the
recursive reflection exploitation technique :

The real issue is in the native sun.reflect.Reflection.getCallerClass
method.

We can see the following information in the Reflection source code :

Returns the class of the method realFramesToSkip frames up the stack
(zero-based), ignoring frames associated with
java.lang.reflect.Method.invoke() and its implementation.

So what is happening here is that they forgot to skip the frames
related to the new Reflection API and only the old reflection API is
taken into account.

This exploit does not only affect Java applets, but every piece of
software that relies on the Java Security Manager for sandboxing
executable code is affected: malicious code can totally disable
Security Manager.

For users who are running native Web browsers with enabled Java
plugin, the workaround is to remove the java/icedtea-web port and
restart all browser instances.

For users who are running Linux Web browser flavors, the workaround is
either to disable the Java plugin in browser or to upgrade linux-sun-*
packages to the non-vulnerable version.

It is not recommended to run untrusted applets using appletviewer,
since this may lead to the execution of the malicious code on
vulnerable versions on JDK/JRE."
  );
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2013-0422-1896849.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eaf95a3d"
  );
  # https://partners.immunityinc.com/idocs/Java%20MBeanInstantiator.findClass%200day%20Analysis.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db189fad"
  );
  # http://www.freebsd.org/ports/portaudit/d5e0317e-5e45-11e2-a113-c48508086173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b341f118"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-sun-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openjdk7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"openjdk7>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jdk>=7.0<7.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-sun-jre>=7.0<7.11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
