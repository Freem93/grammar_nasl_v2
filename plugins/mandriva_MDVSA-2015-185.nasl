#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:185. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82485);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/02 13:36:27 $");

  script_cve_id("CVE-2014-8761", "CVE-2014-8762", "CVE-2014-8763", "CVE-2014-8764", "CVE-2014-9253", "CVE-2015-2172");
  script_bugtraq_id(70404, 70412, 70813, 71671, 72827);
  script_xref(name:"MDVSA", value:"2015:185");

  script_name(english:"Mandriva Linux Security Advisory : dokuwiki (MDVSA-2015:185)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dokuwiki packages fix security vulnerabilities :

inc/template.php in DokuWiki before 2014-05-05a only checks for access
to the root namespace, which allows remote attackers to access
arbitrary images via a media file details ajax call (CVE-2014-8761).

The ajax_mediadiff function in DokuWiki before 2014-05-05a allows
remote attackers to access arbitrary images via a crafted namespace in
the ns parameter (CVE-2014-8762).

DokuWiki before 2014-05-05b, when using Active Directory for LDAP
authentication, allows remote attackers to bypass authentication via a
password starting with a null (\0) character and a valid user name,
which triggers an unauthenticated bind (CVE-2014-8763).

DokuWiki 2014-05-05a and earlier, when using Active Directory for LDAP
authentication, allows remote attackers to bypass authentication via a
user name and password starting with a null (\0) character, which
triggers an anonymous bind (CVE-2014-8764).

dokuwiki-2014-09-29a allows swf (application/x-shockwave-flash)
uploads by default. This may be used for Cross-site scripting (XSS)
attack which enables attackers to inject client-side script into Web
pages viewed by other users. (CVE-2014-9253).

The dokuwiki-2014-09-29b hotfix source disables swf uploads by default
and fixes the CVE-2014-9253 issue.

DokuWiki before 20140929c has a security issue in the ACL plugins
remote API component. The plugin failed to check for superuser
permissions before executing ACL addition or deletion. This means
everybody with permissions to call the XMLRPC API also had permissions
to set up their own ACL rules and thus circumventing any existing
rules (CVE-2015-2172).

DokuWiki before 20140929d is vulnerable to a cross-site scripting
(XSS) issue in the user manager. The user's details were not properly
escaped in the user manager's edit form. This allows a registered user
to edit her own name (using the change profile option) to include
malicious JavaScript code. The code is executed when a super user
tries to edit the user via the user manager."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0118.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dokuwiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dokuwiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"dokuwiki-20140929-1.4.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
