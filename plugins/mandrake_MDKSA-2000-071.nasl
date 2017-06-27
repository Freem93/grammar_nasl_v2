#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2000:071. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61857);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:24 $");

  script_cve_id("CVE-2000-1095");
  script_xref(name:"MDKSA", value:"2000:071-2");

  script_name(english:"Mandrake Linux Security Advisory : modutils (MDKSA-2000:071-2)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"All 2.3.x versions of modutils (since March 12 1999) contain a
vulnerability that can lead to a local root compromise. The modprobe
program uses popen() to execute the 'echo' program argumented with
user input. Because popen() relies on /bin/sh to parse the command
string and execute 'echo', un-escaped shell meta-characters can be
included in user input to execute commands. Although modprobe is not
installed setuid root, this vulnerability can be exploited to gain
root access provided the target system is using kmod. Kmod is a kernel
facility that automatically executes the program modprobe when a
module is requested via request_module(). One program that can take
advantage of this vulnerability is ping. When a device is specified at
the command line that doesn't exist, request_module is called with the
user-supplied arguments passed to the kernel. The kernel then takes
the arguments and executes modprobe with them. Arbitrary commands
included in the argument for module name (device name to ping) are
then executed when popen() is called as root.

A new version of modutils (2.3.20) has been released that fixes this
particular vulnerability. modutils still supports meta expansion,
including back quoted commands, but only for data read from the
configuration file. This assumes that when modutils is run as root out
of the kernel, normal users cannot specify their own configuration
files.

Update :

The previous version of modutils (2.3.20) contained an error in the
new safe guards that caused them to not properly be enabled when run
as root from the kmod process. These new safe guards check the
arguments passed to modules. The 2.3.21 modutils package fixes this
error and correctly checks the arguments when running from kmod,
limiting kernel module arguments to those specified in
/etc/conf.modules (Linux-Mandrake 7.1) or /etc/modules.conf
(Linux-Mandrake 7.2)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected modutils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:modutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"modutils-2.3.21-1.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"modutils-2.3.21-1.3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
