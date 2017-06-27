#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3035. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77882);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/06 04:41:27 $");

  script_cve_id("CVE-2014-7169");
  script_bugtraq_id(70137);
  script_osvdb_id(112004);
  script_xref(name:"DSA", value:"3035");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"Debian DSA-3035-1 : bash - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered that the patch applied to fix CVE-2014-6271
released in DSA-3032-1 for bash, the GNU Bourne-Again Shell, was
incomplete and could still allow some characters to be injected into
another environment (CVE-2014-7169 ). With this update prefix and
suffix for environment variable names which contain shell functions
are added as hardening measure.

Additionally two out-of-bounds array accesses in the bash parser are
fixed which were revealed in Red Hat's internal analysis for these
issues and also independently reported by Todd Sabin."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=762760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=762761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-6271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bash"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3035"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bash packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.2+dfsg-0.1+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"bash", reference:"4.2+dfsg-0.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"bash-builtins", reference:"4.2+dfsg-0.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"bash-doc", reference:"4.2+dfsg-0.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"bash-static", reference:"4.2+dfsg-0.1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
