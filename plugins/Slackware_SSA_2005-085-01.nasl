#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-085-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18812);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_xref(name:"SSA", value:"2005-085-01");

  script_name(english:"Slackware 10.0 / 10.1 / 9.1 / current : Mozilla/Firefox/Thunderbird (SSA:2005-085-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Mozilla packages are available for Slackware 9.1, 10.0, 10.1, and
-current to fix various security issues and bugs. See the Mozilla site
for a complete list of the issues patched:
http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mo
zilla Also updated are Firefox and Thunderbird in Slackware -current,
and GAIM in Slackware 9.1, 10.0, and 10.1 (which uses the Mozilla NSS
libraries). New versions of the mozilla-plugins symlink creation
package are also out for Slackware 9.1, 10.0, and 10.1. Just a little
note on Slackware security -- I believe the state of Slackware right
now is quite secure. I know there have been issues announced and fixed
elsewhere, and I am assessing the reality of them (to be honest, it
seems the level of proof needed to announce a security hole these days
has fallen close to zero -- where are the proof-of-concept exploits?)
It is, as always, my firm intent to keep Slackware as secure as it can
possibly be. I'm still getting back up to speed (and I do not believe
that anything exploitable in real life is being allowed to slide), but
I'm continuing to look over the various reports and would welcome
input at security@slackware.com if you feel anything important has
been overlooked and is in need of attention. Please remember that I do
read BugTraq and many other security lists. I am not asking for
duplicates of BugTraq posts unless you have additional proof or
information on the issues, or can explain how an issue affects your
own servers. This will help me to priorite any work that remains to be
done. Thanks in advance for any helpful comments."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f20085f"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.635646
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4c36cf5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:jre-symlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"9.1", pkgname:"gaim", pkgver:"1.2.0", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"mozilla", pkgver:"1.4.4", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"mozilla-plugins", pkgver:"1.4.4", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"gaim", pkgver:"1.2.0", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mozilla", pkgver:"1.7.6", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mozilla-plugins", pkgver:"1.7.6", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.1", pkgname:"gaim", pkgver:"1.2.0", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"mozilla", pkgver:"1.7.6", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"mozilla-plugins", pkgver:"1.7.6", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"gaim", pkgver:"1.2.0", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"jre-symlink", pkgver:"1.0.2", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mozilla", pkgver:"1.7.6", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mozilla-firefox", pkgver:"1.0.2", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mozilla-thunderbird", pkgver:"1.0.2", pkgarch:"i686", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
