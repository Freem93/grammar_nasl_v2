#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2154. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51819);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/03 11:25:18 $");

  script_cve_id("CVE-2010-4345", "CVE-2011-0017");
  script_osvdb_id(70696);
  script_xref(name:"DSA", value:"2154");

  script_name(english:"Debian DSA-2154-1 : exim4 - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A design flaw (CVE-2010-4345 ) in exim4 allowed the local Debian-exim
user to obtain root privileges by specifying an alternate
configuration file using the -C option or by using the macro override
facility (-D option). Unfortunately, fixing this vulnerability is not
possible without some changes in exim4's behaviour. If you use the -C
or -D options or use the system filter facility, you should evaluate
the changes carefully and adjust your configuration accordingly. The
Debian default configuration is not affected by the changes.

The detailed list of changes is described in the NEWS.Debian file in
the packages. The relevant sections are also reproduced below.

In addition to that, missing error handling for the setuid/setgid
system calls allowed the Debian-exim user to cause root to append log
data to arbitrary files (CVE-2011-0017 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (lenny), these problems have been fixed in
version 4.69-9+lenny3.

Excerpt from the NEWS.Debian file from the packages exim4-daemon-light
and exim4-daemon-heavy :

Exim versions up to and including 4.72 are vulnerable to
CVE-2010-4345. This is a privilege escalation issue that allows the
exim user to gain root privileges by specifying an alternate
configuration file using the -C option. The macro override facility
(-D) might also be misused for this purpose. In reaction to this
security vulnerability upstream has made a number of user visible
changes. This package includes these changes. If exim is invoked with
the -C or -D option the daemon will not regain root privileges though
re-execution. This is usually necessary for local delivery, though.
Therefore it is generally not possible anymore to run an exim daemon
with -D or -C options. However this version of exim has been built
with TRUSTED_CONFIG_LIST=/etc/exim4/trusted_configs.
TRUSTED_CONFIG_LIST defines a list of configuration files which are
trusted; if a config file is owned by root and matches a pathname in
the list, then it may be invoked by the Exim build-time user without
Exim relinquishing root privileges. As a hotfix to not break existing
installations of mailscanner we have also set
WHITELIST_D_MACROS=OUTGOING. i.e. it is still possible to start exim
with -DOUTGOING while being able to do local deliveries. If you
previously were using -D switches you will need to change your setup
to use a separate configuration file. The '.include' mechanism makes
this easy. The system filter is run as exim_user instead of root by
default. If your setup requies root privileges when running the system
filter you will need to set the system_filter_user exim main
configuration option."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"exim4", reference:"4.69-9+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
