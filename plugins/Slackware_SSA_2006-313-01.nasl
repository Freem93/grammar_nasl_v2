#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-313-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23654);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_bugtraq_id(19849);
  script_xref(name:"SSA", value:"2006-313-01");

  script_name(english:"Slackware 10.2 / 11.0 : [fixed URLs]  firefox/thunderbird/seamonkey (SSA:2006-313-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The original advisory for this issue contained incorrect URLs for the
Slackware 11.0 patches. Sorry about that! The URLs for the 10.2
packages were correct (and the Firefox/Thunderbird links given for
11.0 would have been just fine anyway since 10.2 and 11.0 are using
the same packages for those)."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3462ca90"
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?637d935f"
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#thunderbird
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7275234"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.387734
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3017a02"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.500365
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5175174e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mozilla-firefox, mozilla-thunderbird and / or
seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"mozilla-firefox", pkgver:"1.5.0.8", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.2", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.8", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"11.0", pkgname:"mozilla-firefox", pkgver:"1.5.0.8", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"11.0", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.8", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"11.0", pkgname:"seamonkey", pkgver:"1.0.6", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
