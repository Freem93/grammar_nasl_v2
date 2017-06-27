#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-297. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15134);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2014/09/08 10:40:59 $");

  script_cve_id("CVE-2003-0033", "CVE-2003-0209");
  script_bugtraq_id(6963, 7178);
  script_osvdb_id(4444);
  script_xref(name:"CERT", value:"139129");
  script_xref(name:"CERT", value:"916785");
  script_xref(name:"DSA", value:"297");

  script_name(english:"Debian DSA-297-1 : snort - integer overflow, buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in Snort, a popular network
intrusion detection system. Snort comes with modules and plugins that
perform a variety of functions such as protocol analysis. The
following issues have been identified :

Heap overflow in Snort 'stream4' preprocessor (VU#139129,
CAN-2003-0209, Bugtraq Id 7178)Researchers at CORE Security
Technologies have discovered a remotely exploitable integer overflow
that results in overwriting the heap in the 'stream4' preprocessor
module. This module allows Snort to reassemble TCP packet fragments
for further analysis. An attacker could insert arbitrary code that
would be executed as the user running Snort, probably root.Buffer
overflow in Snort RPC preprocessor (VU#916785, CAN-2003-0033, Bugtraq
Id 6963)Researchers at Internet Security Systems X-Force have
discovered a remotely exploitable buffer overflow in the Snort RPC
preprocessor module. Snort incorrectly checks the lengths of what is
being normalized against the current packet size. An attacker could
exploit this to execute arbitrary code under the privileges of the
Snort process, probably root."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-297"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the snort package immediately.

For the stable distribution (woody) these problems have been fixed in
version 1.8.4beta1-3.1.

The old stable distribution (potato) is not affected by these problems
since it doesn't contain the problematic code.

You are also advised to upgrade to the most recent version of Snort,
since Snort, as any intrusion detection system, is rather useless if
it is based on old and out-dated data and not kept up to date. Such
installations would be unable to detect intrusions using modern
methods. The current version of Snort is 2.0.0, while the version in
the stable distribution (1.8) is quite old and the one in the old
stable distribution is beyond hope.

Since Debian does not update arbitrary packages in stable releases,
even Snort is not going to see updates other than to fix security
problems, you are advised to upgrade to the most recent version from
third-party sources."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snort");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"3.0", prefix:"snort", reference:"1.8.4beta1-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"snort-common", reference:"1.8.4beta1-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"snort-doc", reference:"1.8.4beta1-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"snort-mysql", reference:"1.8.4beta1-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"snort-rules-default", reference:"1.8.4beta1-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
