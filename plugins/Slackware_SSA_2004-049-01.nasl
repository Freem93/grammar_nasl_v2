#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2004-049-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18789);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/04/25 14:53:15 $");

  script_cve_id("CVE-2004-0077");
  script_osvdb_id(3986);
  script_xref(name:"SSA", value:"2004-049-01");

  script_name(english:"Slackware 9.1 / current : Kernel security update (SSA:2004-049-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kernels are available for Slackware 9.1 and -current to fix a
bounds-checking problem in the kernel's mremap() call which could be
used by a local attacker to gain root privileges. Please note that
this is not the same issue as CAN-2003-0985 which was fixed in early
January. The kernels in Slackware 8.1 and 9.0 that were updated in
January are not vulnerable to this new issue because the patch from
Solar Designer that was used to fix the CAN-2003-0985 bugs also
happened to fix the problem that was discovered later. Sites running
Slackware 9.1 or -current should upgrade to a new kernel. After
installing the new kernel, be sure to run 'lilo'."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.541911
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebf1ce63"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-ide and / or kernel-source packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-ide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"9.1", pkgname:"kernel-ide", pkgver:"2.4.24", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"9.1", pkgname:"kernel-source", pkgver:"2.4.24", pkgarch:"noarch", pkgnum:"2")) flag++;

if (slackware_check(osver:"current", pkgname:"kernel-ide", pkgver:"2.4.24", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-source", pkgver:"2.4.24", pkgarch:"noarch", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
